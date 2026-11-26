//go:build !windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
)

func windowsBuild() string {
	// 协议要求固定伪装成 PC 客户端 ostag
	return "Windows 11(26200),64 bit "
}

type unixRouteEntry struct {
	iface   string
	dest    net.IP
	mask    net.IP
	gateway net.IP
	metric  uint32
}

func parseProcNetRoute() []unixRouteEntry {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	parseHexIP := func(h string) net.IP {
		v, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			return nil
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	var out []unixRouteEntry
	lines := strings.Split(string(data), "\n")
	for i := 1; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) < 8 {
			continue
		}
		dest := parseHexIP(fields[1])
		gw := parseHexIP(fields[2])
		mask := parseHexIP(fields[7])
		metric, _ := strconv.ParseUint(fields[6], 10, 32)
		if dest == nil || mask == nil || gw == nil {
			continue
		}
		out = append(out, unixRouteEntry{
			iface:   fields[0],
			dest:    dest.To4(),
			mask:    mask.To4(),
			gateway: gw.To4(),
			metric:  uint32(metric),
		})
	}
	return out
}

func parseResolvConfDNS() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "nameserver") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				if ip := net.ParseIP(f[1]).To4(); ip != nil && !ip.IsLoopback() && !isFakeIP(ip) {
					out = append(out, ip.String())
				}
			}
		}
	}
	return out
}

// EnumerateAdapters 在 Linux / macOS / OpenWrt 枚举 IPv4 接口并标注物理/TUN 属性
func EnumerateAdapters() []AdapterInfo {
	ifaces, _ := net.Interfaces()
	routes := parseProcNetRoute()
	sysDNS := parseResolvConfDNS()

	type ifRoute struct {
		gateway    string
		hasDefault bool
		metric     uint32
	}
	byName := map[string]ifRoute{}
	for _, r := range routes {
		cur := byName[r.iface]
		if cur.gateway == "" && r.gateway != nil && !r.gateway.IsUnspecified() {
			cur.gateway = r.gateway.String()
		}
		if r.dest != nil && r.mask != nil && r.dest.Equal(net.IPv4zero) && r.mask.Equal(net.IPv4zero) {
			if !cur.hasDefault || r.metric < cur.metric {
				cur.hasDefault = true
				cur.metric = r.metric
				if r.gateway != nil && !r.gateway.IsUnspecified() {
					cur.gateway = r.gateway.String()
				}
			}
		}
		byName[r.iface] = cur
	}

	var result []AdapterInfo
	for _, f := range ifaces {
		if f.Flags&net.FlagLoopback != 0 {
			continue
		}
		ip4, mask := "", ""
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
		rt := byName[f.Name]
		result = append(result, AdapterInfo{
			IfIndex:         uint32(f.Index),
			Name:            f.Name,
			Description:     f.Name,
			TypeLabel:       adapterTypeLabel(f.Name, f.Name, 0, isPhys, isTUN),
			IP4:             ip4,
			Mask:            mask,
			Gateway:         rt.gateway,
			MAC:             mac,
			DNSServers:      sysDNS,
			IsUp:            f.Flags&net.FlagUp != 0,
			IsPhysical:      isPhys,
			IsTUN:           isTUN,
			TUNReason:       reason,
			HasDefaultRoute: rt.hasDefault,
			DefaultMetric:   rt.metric,
		})
	}
	return result
}

func DetectProxyEnv(adapters []AdapterInfo) ProxyEnvInfo {
	var tuns []string
	for _, a := range adapters {
		if a.IsTUN && a.IsUp {
			tuns = append(tuns, a.Name)
		}
	}
	routes := parseProcNetRoute()
	anySplit := false
	for _, r := range routes {
		if r.dest != nil && r.mask != nil {
			if (r.dest.Equal(net.IPv4zero) && r.mask.Equal(net.IPv4(128, 0, 0, 0))) ||
				(r.dest.Equal(net.IPv4(128, 0, 0, 0)) && r.mask.Equal(net.IPv4(128, 0, 0, 0))) {
				anySplit = true
				break
			}
		}
	}
	envVars := collectEnvProxyVars()
	tunActive := len(tuns) > 0 || anySplit
	mode := "物理直连 (无活跃 TUN)"
	if tunActive || len(envVars) > 0 {
		mode = "源 IP 绑定直连 + 无代理传输 (已旁路环境变量代理)"
	}
	return ProxyEnvInfo{
		TUNActive:    tunActive,
		TUNAdapters:  tuns,
		SplitRoutes:  anySplit,
		EnvProxyVars: envVars,
		BypassMode:   mode,
	}
}

// SetSocketUnicastIf4 在类 Unix 平台上依赖 Dialer.LocalAddr 源地址绑定，此处安全无副作用返回
func SetSocketUnicastIf4(fd uintptr, ifIndex uint32) error {
	return nil
}

func platformBestRouteGW(dst, src net.IP) string {
	src4 := src.To4()
	if src4 == nil {
		return ""
	}
	for _, a := range EnumerateAdapters() {
		if a.IP4 == src4.String() && a.Gateway != "" {
			return a.Gateway
		}
	}
	return ""
}

func DPAPIProtect(plain []byte) (string, error) {
	if len(plain) == 0 {
		return "", nil
	}
	return "plainb64:" + base64.StdEncoding.EncodeToString(plain), nil
}

func DPAPIUnprotect(b64 string) ([]byte, error) {
	s := strings.TrimSpace(b64)
	if s == "" {
		return nil, nil
	}
	s = strings.TrimPrefix(s, "plainb64:")
	return base64.StdEncoding.DecodeString(s)
}
