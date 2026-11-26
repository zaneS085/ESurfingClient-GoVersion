//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modIphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procGetAdaptersInfo  = modIphlpapi.NewProc("GetAdaptersInfo")
	procGetPerAdapterInf = modIphlpapi.NewProc("GetPerAdapterInfo")
	procGetIpForwardTbl  = modIphlpapi.NewProc("GetIpForwardTable")
	procGetBestRoute     = modIphlpapi.NewProc("GetBestRoute")

	modCrypt32           = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotect   = modCrypt32.NewProc("CryptUnprotectData")

	modKernel32Net = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree  = modKernel32Net.NewProc("LocalFree")
)

type mibIPForwardRow struct {
	dwForwardDest, dwForwardMask, dwForwardPolicy, dwForwardNextHop                          uint32
	dwForwardIfIndex, dwForwardType, dwForwardProto, dwForwardAge                            uint32
	dwForwardNextHopAS                                                                       uint32
	dwForwardMetric1, dwForwardMetric2, dwForwardMetric3, dwForwardMetric4, dwForwardMetric5 uint32
}

func windowsBuild() string {
	// 官方 ostag 格式 (抓包实锤): "Windows 11(26200),64 bit " (尾部带空格)
	var hKey syscall.Handle
	subkey, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err == nil && syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_READ, &hKey) == nil {
		defer syscall.RegCloseKey(hKey)
		valName, _ := syscall.UTF16PtrFromString("CurrentBuildNumber")
		var typ uint32
		var buf [64]uint16
		n := uint32(len(buf) * 2)
		if syscall.RegQueryValueEx(hKey, valName, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) == nil && n >= 2 {
			build := strings.TrimSpace(syscall.UTF16ToString(buf[:n/2]))
			if build != "" {
				ver := "10"
				if bnum, e := strconv.Atoi(build); e == nil && bnum >= 22000 {
					ver = "11"
				}
				return fmt.Sprintf("Windows %s(%s),64 bit ", ver, build)
			}
		}
	}
	return "Windows 11(26200),64 bit "
}

func platformBestRouteGW(dst, src net.IP) string {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return ""
	}
	var row mibIPForwardRow
	r, _, _ := procGetBestRoute.Call(
		uintptr(binary.LittleEndian.Uint32(dst4)),
		uintptr(binary.LittleEndian.Uint32(src4)),
		uintptr(unsafe.Pointer(&row)))
	if r != 0 || row.dwForwardNextHop == 0 {
		return ""
	}
	gw := make(net.IP, 4)
	binary.LittleEndian.PutUint32(gw, row.dwForwardNextHop)
	if gw.IsUnspecified() {
		return ""
	}
	return gw.String()
}

const (
	errBufferOverflow        = 111
	errInsufficientBuffer    = 122
	ipUnicastIfOpt           = 31
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4
)

type ipAddrString struct {
	Next      *ipAddrString
	IPAddress [16]byte
	IPMask    [16]byte
	Context   uint32
}

type ipAdapterInfo struct {
	Next                *ipAdapterInfo
	ComboIndex          uint32
	AdapterName         [260]byte
	Description         [132]byte
	AddressLength       uint32
	Address             [8]byte
	Index               uint32
	Type                uint32
	DhcpEnabled         uint32
	CurrentIPAddress    *ipAddrString
	IPAddressList       ipAddrString
	GatewayList         ipAddrString
	DhcpServer          ipAddrString
	HaveWins            int32
	PrimaryWinsServer   ipAddrString
	SecondaryWinsServer ipAddrString
	LeaseObtained       int64
	LeaseExpires        int64
}

type ipPerAdapterInfo struct {
	AutoconfigEnabled uint32
	AutoconfigActive  uint32
	CurrentDNSServer  *ipAddrString
	DNSServerList     ipAddrString
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func cstrBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return strings.TrimSpace(string(b[:i]))
		}
	}
	return strings.TrimSpace(string(b))
}

func collectAddrList(head *ipAddrString) (ips []string, firstMask string) {
	seen := map[string]bool{}
	for cur := head; cur != nil; cur = cur.Next {
		ip := cstrBytes(cur.IPAddress[:])
		mask := cstrBytes(cur.IPMask[:])
		if ip != "" && ip != "0.0.0.0" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
			if firstMask == "" && mask != "" && mask != "0.0.0.0" {
				firstMask = mask
			}
		}
	}
	return ips, firstMask
}

func readRegString(hKey syscall.Handle, name string) string {
	valName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var typ uint32
	var buf [512]uint16
	n := uint32(len(buf) * 2)
	if syscall.RegQueryValueEx(hKey, valName, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) != nil || n < 2 {
		return ""
	}
	limit := int(n / 2)
	if limit > len(buf) {
		limit = len(buf)
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf[:limit]))
}

func parseRegDNSList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\t'
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range fields {
		ip := net.ParseIP(strings.TrimSpace(f))
		if !isValidResolvedIPv4(ip) {
			continue
		}
		k := ip.To4().String()
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// queryAdapterRegistryDNS 从 Windows TCP/IP 接口注册表找回被用户自定义 DNS 覆盖的原始 DHCP DNS (DhcpNameServer)
func queryAdapterRegistryDNS(adapterGUID string) (dhcpDNS []string, hasStaticCustom bool) {
	guid := strings.TrimSpace(adapterGUID)
	if guid == "" {
		return nil, false
	}
	subkey, err := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + guid)
	if err != nil {
		return nil, false
	}
	var hKey syscall.Handle
	if syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_READ, &hKey) != nil {
		return nil, false
	}
	defer syscall.RegCloseKey(hKey)
	dhcpDNS = parseRegDNSList(readRegString(hKey, "DhcpNameServer"))
	staticRaw := strings.TrimSpace(readRegString(hKey, "NameServer"))
	hasStaticCustom = staticRaw != ""
	return dhcpDNS, hasStaticCustom
}

func mergeUniqueStrings(slices ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, sl := range slices {
		for _, s := range sl {
			s = strings.TrimSpace(s)
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func queryPerAdapterDNS(ifIndex uint32) []string {
	if ifIndex == 0 || procGetPerAdapterInf.Find() != nil {
		return nil
	}
	var sz uint32
	r, _, _ := procGetPerAdapterInf.Call(uintptr(ifIndex), 0, uintptr(unsafe.Pointer(&sz)))
	if r != errBufferOverflow && r != errInsufficientBuffer {
		return nil
	}
	if sz < uint32(unsafe.Sizeof(ipPerAdapterInfo{})) {
		sz = uint32(unsafe.Sizeof(ipPerAdapterInfo{}))
	}
	buf := make([]byte, sz)
	r, _, _ = procGetPerAdapterInf.Call(uintptr(ifIndex), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
	if r != 0 {
		return nil
	}
	info := (*ipPerAdapterInfo)(unsafe.Pointer(&buf[0]))
	dnsList, _ := collectAddrList(&info.DNSServerList)
	runtime.KeepAlive(buf)
	return dnsList
}

type routeSummary struct {
	hasDefault    bool
	defaultMetric uint32
	hasSplit      bool
}

func queryIPForwardSummary() (byIf map[uint32]routeSummary, anySplit bool) {
	byIf = map[uint32]routeSummary{}
	if procGetIpForwardTbl.Find() != nil {
		return byIf, false
	}
	var sz uint32
	r, _, _ := procGetIpForwardTbl.Call(0, uintptr(unsafe.Pointer(&sz)), 0)
	if r != errInsufficientBuffer && r != errBufferOverflow {
		return byIf, false
	}
	if sz < 4 {
		return byIf, false
	}
	buf := make([]byte, sz)
	r, _, _ = procGetIpForwardTbl.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)), 0)
	if r != 0 {
		return byIf, false
	}
	num := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(mibIPForwardRow{}))
	if uint64(4)+uint64(num)*uint64(rowSize) > uint64(len(buf)) {
		num = uint32((len(buf) - 4) / int(rowSize))
	}
	u32IP := func(v uint32) net.IP {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	for i := uint32(0); i < num; i++ {
		off := 4 + i*rowSize
		row := (*mibIPForwardRow)(unsafe.Pointer(&buf[off]))
		dest := u32IP(row.dwForwardDest).To4()
		mask := u32IP(row.dwForwardMask).To4()
		if dest == nil || mask == nil {
			continue
		}
		isDefault := dest.Equal(net.IPv4zero) && mask.Equal(net.IPv4zero)
		isSplit := (dest.Equal(net.IPv4zero) && mask.Equal(net.IPv4(128, 0, 0, 0))) ||
			(dest.Equal(net.IPv4(128, 0, 0, 0)) && mask.Equal(net.IPv4(128, 0, 0, 0)))
		if !isDefault && !isSplit {
			continue
		}
		cur := byIf[row.dwForwardIfIndex]
		if isDefault {
			if !cur.hasDefault || row.dwForwardMetric1 < cur.defaultMetric {
				cur.hasDefault = true
				cur.defaultMetric = row.dwForwardMetric1
			}
		}
		if isSplit {
			cur.hasSplit = true
			anySplit = true
		}
		byIf[row.dwForwardIfIndex] = cur
	}
	return byIf, anySplit
}

// EnumerateAdapters 枚举系统 IPv4 网卡并附带真实网关、DNS、默认路由与 TUN 识别
func EnumerateAdapters() []AdapterInfo {
	ifaces, _ := net.Interfaces()
	goIfaceByIdx := map[uint32]net.Interface{}
	for _, f := range ifaces {
		if f.Index > 0 {
			goIfaceByIdx[uint32(f.Index)] = f
		}
	}
	routes, _ := queryIPForwardSummary()

	var result []AdapterInfo
	seenIdx := map[uint32]bool{}

	if procGetAdaptersInfo.Find() == nil {
		var sz uint32
		r, _, _ := procGetAdaptersInfo.Call(0, uintptr(unsafe.Pointer(&sz)))
		if (r == errBufferOverflow || r == errInsufficientBuffer) && sz > 0 {
			buf := make([]byte, sz)
			r, _, _ = procGetAdaptersInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
			if r == 0 {
				for cur := (*ipAdapterInfo)(unsafe.Pointer(&buf[0])); cur != nil; cur = cur.Next {
					idx := cur.Index
					seenIdx[idx] = true
					ips, mask := collectAddrList(&cur.IPAddressList)
					ip4 := ""
					if len(ips) > 0 {
						ip4 = ips[0]
					}
					gws, _ := collectAddrList(&cur.GatewayList)
					gw := ""
					if len(gws) > 0 {
						gw = gws[0]
					}
					mac := ""
					if cur.AddressLength == 6 {
						mac = fmt.Sprintf("%02X-%02X-%02X-%02X-%02X-%02X",
							cur.Address[0], cur.Address[1], cur.Address[2],
							cur.Address[3], cur.Address[4], cur.Address[5])
					}
					name := cstrBytes(cur.Description[:])
					isUp := true
					if f, ok := goIfaceByIdx[idx]; ok {
						if f.Name != "" {
							name = f.Name
						}
						isUp = f.Flags&net.FlagUp != 0
						if mac == "" && isValidMAC(f.HardwareAddr) {
							mac = strings.ReplaceAll(strings.ToUpper(f.HardwareAddr.String()), ":", "-")
						}
						if ip4 == "" {
							if addrs, err := f.Addrs(); err == nil {
								for _, a := range addrs {
									if ipn, ok2 := a.(*net.IPNet); ok2 {
										if a4 := ipn.IP.To4(); a4 != nil {
											ip4 = a4.String()
											break
										}
									}
								}
							}
						}
					}
					desc := cstrBytes(cur.Description[:])
					guid := cstrBytes(cur.AdapterName[:])
					isPhys, isTUN, reason := classifyAdapter(name, desc, ip4, mac, cur.Type)
					rs := routes[idx]
					perDNS := queryPerAdapterDNS(idx)
					dhcpDNS, hasStaticCustom := queryAdapterRegistryDNS(guid)
					// 优先保留 DHCP 下发的校园网/电信内网 DNS，再合并系统当前 DNS
					dnsServers := mergeUniqueStrings(dhcpDNS, perDNS)
					result = append(result, AdapterInfo{
						IfIndex:         idx,
						AdapterGUID:     guid,
						Name:            name,
						Description:     desc,
						IfType:          cur.Type,
						TypeLabel:       adapterTypeLabel(name, desc, cur.Type, isPhys, isTUN),
						IP4:             ip4,
						Mask:            mask,
						Gateway:         gw,
						MAC:             mac,
						DNSServers:      dnsServers,
						DHCPDNSServers:  dhcpDNS,
						CustomStaticDNS: hasStaticCustom,
						IsUp:            isUp,
						IsPhysical:      isPhys,
						IsTUN:           isTUN,
						TUNReason:       reason,
						HasDefaultRoute: rs.hasDefault,
						DefaultMetric:   rs.defaultMetric,
					})
				}
				runtime.KeepAlive(buf)
			}
		}
	}

	// 补全 GetAdaptersInfo 遗漏的虚拟/TUN 接口 (如某些 Tailscale / Wintun 接口)
	for _, f := range ifaces {
		idx := uint32(f.Index)
		if idx == 0 || seenIdx[idx] || f.Flags&net.FlagLoopback != 0 {
			continue
		}
		ip4 := ""
		mask := ""
		if addrs, err := f.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if a4 := ipn.IP.To4(); a4 != nil {
						ip4 = a4.String()
						mask = net.IP(ipn.Mask).String()
						break
					}
				}
			}
		}
		if ip4 == "" {
			continue
		}
		mac := ""
		if isValidMAC(f.HardwareAddr) {
			mac = strings.ReplaceAll(strings.ToUpper(f.HardwareAddr.String()), ":", "-")
		}
		isPhys, isTUN, reason := classifyAdapter(f.Name, f.Name, ip4, mac, 0)
		rs := routes[idx]
		result = append(result, AdapterInfo{
			IfIndex:         idx,
			Name:            f.Name,
			Description:     f.Name,
			TypeLabel:       adapterTypeLabel(f.Name, f.Name, 0, isPhys, isTUN),
			IP4:             ip4,
			Mask:            mask,
			MAC:             mac,
			DNSServers:      queryPerAdapterDNS(idx),
			IsUp:            f.Flags&net.FlagUp != 0,
			IsPhysical:      isPhys,
			IsTUN:           isTUN,
			TUNReason:       reason,
			HasDefaultRoute: rs.hasDefault,
			DefaultMetric:   rs.defaultMetric,
		})
	}

	return result
}

// DetectProxyEnv 检测当前 TUN 虚拟网卡、分流默认路由 (0.0.0.0/1)、WinINET 与环境变量代理
func DetectProxyEnv(adapters []AdapterInfo) ProxyEnvInfo {
	_, anySplit := queryIPForwardSummary()
	var tuns []string
	for _, a := range adapters {
		if a.IsTUN && a.IsUp {
			tuns = append(tuns, a.Name)
		}
	}

	sysOn := false
	sysAddr := ""
	var hKey syscall.Handle
	subkey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err == nil && syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, subkey, 0, syscall.KEY_READ, &hKey) == nil {
		defer syscall.RegCloseKey(hKey)
		if valName, e := syscall.UTF16PtrFromString("ProxyEnable"); e == nil {
			var typ, val uint32
			n := uint32(4)
			if syscall.RegQueryValueEx(hKey, valName, nil, &typ, (*byte)(unsafe.Pointer(&val)), &n) == nil && val != 0 {
				sysOn = true
			}
		}
		if valName, e := syscall.UTF16PtrFromString("ProxyServer"); e == nil {
			var typ uint32
			var buf [260]uint16
			n := uint32(len(buf) * 2)
			if syscall.RegQueryValueEx(hKey, valName, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) == nil && n >= 2 {
				sysAddr = strings.TrimSpace(syscall.UTF16ToString(buf[:n/2]))
			}
		}
	}

	var envVars = collectEnvProxyVars()

	tunActive := len(tuns) > 0 || anySplit
	mode := "物理直连 (无活跃 TUN)"
	if tunActive || sysOn || len(envVars) > 0 {
		mode = "IP_UNICAST_IF 物理直连 + 无代理传输 (已自动绕过 TUN/系统代理)"
	}

	return ProxyEnvInfo{
		TUNActive:       tunActive,
		TUNAdapters:     tuns,
		SplitRoutes:     anySplit,
		SystemProxyOn:   sysOn,
		SystemProxyAddr: sysAddr,
		EnvProxyVars:    envVars,
		BypassMode:      mode,
	}
}

// SetSocketUnicastIf4 通过 WinSock IP_UNICAST_IF(31) 把 IPv4 Socket 强行钉死在指定物理网卡，
// 直接绕过 TUN 全局/分流路由 (0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1)，无需管理员权限。
// 注意: Windows IPv4 的 IP_UNICAST_IF 要求接口索引使用网络字节序 (Big-Endian htonl)。
func SetSocketUnicastIf4(fd uintptr, ifIndex uint32) error {
	if ifIndex == 0 {
		return nil
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ifIndex)
	netOrder := int32(binary.NativeEndian.Uint32(b[:]))
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIfOpt, int(netOrder))
}

// DPAPIProtect 使用当前 Windows 登录用户密钥 (CryptProtectData) 加密敏感凭据为 base64
func DPAPIProtect(plain []byte) (string, error) {
	if len(plain) == 0 {
		return "", nil
	}
	var inBlob, outBlob dataBlob
	inBlob.cbData = uint32(len(plain))
	inBlob.pbData = &plain[0]
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	runtime.KeepAlive(plain)
	if r == 0 {
		return "", fmt.Errorf("CryptProtectData: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	out := unsafe.Slice(outBlob.pbData, int(outBlob.cbData))
	cp := append([]byte(nil), out...)
	return base64.StdEncoding.EncodeToString(cp), nil
}

// DPAPIUnprotect 使用 CryptUnprotectData 解密 base64 凭据
func DPAPIUnprotect(b64 string) ([]byte, error) {
	if strings.TrimSpace(b64) == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var inBlob, outBlob dataBlob
	inBlob.cbData = uint32(len(raw))
	inBlob.pbData = &raw[0]
	r, _, callErr := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	runtime.KeepAlive(raw)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %v", callErr)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	out := unsafe.Slice(outBlob.pbData, int(outBlob.cbData))
	return append([]byte(nil), out...), nil
}
