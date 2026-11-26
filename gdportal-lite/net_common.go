package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

// AdapterInfo 描述本机 IPv4 网络适配器及 TUN/物理分类结果
type AdapterInfo struct {
	IfIndex         uint32   `json:"ifIndex"`
	AdapterGUID     string   `json:"-"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	IfType          uint32   `json:"ifType"`
	TypeLabel       string   `json:"typeLabel"`
	IP4             string   `json:"ip4"`
	Mask            string   `json:"mask"`
	Gateway         string   `json:"gateway"`
	MAC             string   `json:"mac"`
	DNSServers      []string `json:"dnsServers"`
	DHCPDNSServers  []string `json:"dhcpDnsServers,omitempty"`
	CustomStaticDNS bool     `json:"customStaticDns,omitempty"`
	IsUp            bool     `json:"isUp"`
	IsPhysical      bool     `json:"isPhysical"`
	IsTUN           bool     `json:"isTUN"`
	TUNReason       string   `json:"tunReason,omitempty"`
	HasDefaultRoute bool     `json:"hasDefaultRoute"`
	DefaultMetric   uint32   `json:"defaultMetric,omitempty"`
}

// ProxyEnvInfo 描述当前系统代理、TUN 虚拟网卡与默认路由劫持状态
type ProxyEnvInfo struct {
	TUNActive       bool     `json:"tunActive"`
	TUNAdapters     []string `json:"tunAdapters,omitempty"`
	SplitRoutes     bool     `json:"splitRoutes"`
	SystemProxyOn   bool     `json:"systemProxyOn"`
	SystemProxyAddr string   `json:"systemProxyAddr,omitempty"`
	EnvProxyVars    []string `json:"envProxyVars,omitempty"`
	BypassMode      string   `json:"bypassMode"`
}

// isFakeIP 检测 RFC2544 保留网段 198.18.0.0/15 (代理软件 TUN Fake-IP 常用地址段)
func isFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 198 && (ip4[1]&0xfe) == 18
}

func hasToken(s, tok string) bool {
	fields := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	for _, f := range fields {
		if f == tok {
			return true
		}
	}
	return false
}

// classifyAdapter 识别物理网卡、TUN 虚拟网卡与虚拟机/隧道虚拟网卡
func classifyAdapter(name, desc, ip4, mac string, ifType uint32) (isPhysical, isTUN bool, reason string) {
	if ip := net.ParseIP(ip4); ip != nil {
		if ip.IsLoopback() {
			return false, false, "环回接口"
		}
		if isFakeIP(ip) {
			return false, true, "RFC2544 Fake-IP 段"
		}
		if ip.IsLinkLocalUnicast() {
			lower := strings.ToLower(name + " " + desc)
			if strings.Contains(lower, "tailscale") || strings.Contains(lower, "wintun") || strings.Contains(lower, "tunnel") {
				return false, true, "TUN 隧道接口 (169.254.x.x)"
			}
			return false, false, "链路本地地址 (169.254.x.x)"
		}
	}
	lower := strings.ToLower(name + " " + desc)
	tunSubstrs := []string{
		"wintun", "clash", "mihomo", "sing-box", "singbox", "utun",
		"tap-windows", "tailscale", "wireguard", "openvpn", "shadowsocks",
		"v2ray", "xray", "nekobox", "nekoray", "flclash", "hiddify",
		"mullvad", "nordlynx", "cloudflare warp", "tunnel",
	}
	for _, kw := range tunSubstrs {
		if strings.Contains(lower, kw) {
			return false, true, "TUN/VPN 特征: " + kw
		}
	}
	if hasToken(lower, "tun") || hasToken(lower, "meta") || hasToken(lower, "warp") {
		return false, true, "TUN/VPN 网卡名称"
	}
	if ifType == 131 { // IF_TYPE_TUNNEL
		return false, true, "Windows IF_TYPE_TUNNEL (131)"
	}

	virtSubstrs := []string{
		"zerotier", "hyper-v", "vethernet", "vmware", "vmnet", "virtualbox",
		"vbox", "npcap", "bluetooth", "蓝牙", "ksa host", "teredo", "isatap",
		"loopback", "pseudo", "virtual",
	}
	for _, kw := range virtSubstrs {
		if strings.Contains(lower, kw) {
			return false, false, "虚拟/桥接网卡: " + kw
		}
	}
	if ifType == 53 || ifType == 24 { // PROP_VIRTUAL / LOOPBACK
		return false, false, fmt.Sprintf("虚拟接口类型 (%d)", ifType)
	}
	normMAC := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(mac)), ":", "-")
	if normMAC == "" || normMAC == "00-00-00-00-00-00" || strings.HasPrefix(normMAC, "00-00-00") {
		return false, false, "无有效物理 MAC"
	}
	return true, false, ""
}

func adapterTypeLabel(name, desc string, ifType uint32, isPhysical, isTUN bool) string {
	if isTUN {
		return "TUN/VPN"
	}
	if !isPhysical {
		return "Virtual"
	}
	lower := strings.ToLower(name + " " + desc)
	if ifType == 71 || strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wifi") ||
		strings.Contains(lower, "wireless") || strings.Contains(lower, "wlan") || strings.Contains(lower, "802.11") {
		return "Wi-Fi"
	}
	return "Ethernet"
}

func findAdapterByIP(adapters []AdapterInfo, ip string) (AdapterInfo, bool) {
	for _, a := range adapters {
		if a.IP4 == ip {
			return a, true
		}
	}
	return AdapterInfo{}, false
}

func findAdapterByIndex(adapters []AdapterInfo, idx uint32) (AdapterInfo, bool) {
	for _, a := range adapters {
		if a.IfIndex == idx {
			return a, true
		}
	}
	return AdapterInfo{}, false
}

func collectEnvProxyVars() []string {
	var envVars []string
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			envVars = append(envVars, k+"="+v)
		}
	}
	return envVars
}

func cleanPhysicalDNS(dnsServers []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range dnsServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// 允许测试传入 ip:port；若为纯 IP 则做 Fake-IP / 环回 / 链路本地地址过滤
		if _, _, err := net.SplitHostPort(s); err == nil {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			continue
		}
		ip := net.ParseIP(s)
		if !isValidResolvedIPv4(ip) {
			continue
		}
		k := ip.To4().String()
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, fb := range telecomFallbackDNS {
		if !seen[fb] {
			seen[fb] = true
			out = append(out, fb)
		}
	}
	return out
}

// newPinnedResolver 创建绕过 TUN / Fake-IP DNS 的物理网卡专用解析器
func newPinnedResolver(srcIP net.IP, ifIndex uint32, dnsServers []string) *net.Resolver {
	targets := cleanPhysicalDNS(dnsServers)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 1800 * time.Millisecond}
			if srcIP != nil && srcIP.To4() != nil {
				d.LocalAddr = &net.UDPAddr{IP: srcIP.To4()}
			}
			if ifIndex > 0 {
				d.Control = func(_, _ string, rc syscall.RawConn) error {
					var sockErr error
					if err := rc.Control(func(fd uintptr) {
						sockErr = SetSocketUnicastIf4(fd, ifIndex)
					}); err != nil {
						return err
					}
					return sockErr
				}
			}
			var lastErr error
			for _, dnsIP := range targets {
				conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(dnsIP, "53"))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = errors.New("无可用物理网卡 DNS")
			}
			return nil, lastErr
		},
	}
}

func newPinnedDialer(srcIP net.IP, ifIndex uint32, dnsServers []string, dialTimeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: dialTimeout}
	if srcIP != nil && srcIP.To4() != nil {
		d.LocalAddr = &net.TCPAddr{IP: srcIP.To4()}
	}
	if ifIndex > 0 {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			var sockErr error
			if err := rc.Control(func(fd uintptr) {
				sockErr = SetSocketUnicastIf4(fd, ifIndex)
			}); err != nil {
				return err
			}
			return sockErr
		}
	}
	if ifIndex > 0 || (srcIP != nil && srcIP.To4() != nil) {
		d.Resolver = newPinnedResolver(srcIP, ifIndex, dnsServers)
	}
	return d
}

// resolvePinnedIP4Candidates 并发竞速物理网卡 DNS 并回退至内置 Portal IP，返回 ip:port 候选列表
func resolvePinnedIP4Candidates(ctx context.Context, srcIP net.IP, ifIndex uint32, dnsServers []string, addr string) ([]string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}, nil
	}
	ips, _, err := resolvePinnedIP4List(ctx, srcIP, ifIndex, dnsServers, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, port))
	}
	return out, nil
}

// resolvePinnedIP4 先用物理网卡专用 DNS 解析 IPv4，拒绝 Fake-IP (198.18.0.0/15)
func resolvePinnedIP4(ctx context.Context, d *net.Dialer, addr string) (string, error) {
	var srcIP net.IP
	if d != nil && d.LocalAddr != nil {
		switch a := d.LocalAddr.(type) {
		case *net.TCPAddr:
			srcIP = a.IP
		case *net.UDPAddr:
			srcIP = a.IP
		}
	}
	cands, err := resolvePinnedIP4Candidates(ctx, srcIP, 0, nil, addr)
	if err == nil && len(cands) > 0 {
		return cands[0], nil
	}
	return "", err
}

// boundClientWithNIC 生成绑定物理出口 + 无代理传输 + 并发防劫持 DNS 解析的 HTTP 客户端
func boundClientWithNIC(srcIP net.IP, ifIndex uint32, dnsServers []string, dialTimeout, totalTimeout time.Duration) *http.Client {
	d := newPinnedDialer(srcIP, ifIndex, dnsServers, dialTimeout)
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			cands, err := resolvePinnedIP4Candidates(ctx, srcIP, ifIndex, dnsServers, addr)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, cand := range cands {
				conn, derr := d.DialContext(ctx, "tcp4", cand)
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
				if ctx.Err() != nil {
					break
				}
			}
			return nil, lastErr
		},
		DisableCompression: true,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       totalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// queryInterfaceIPv4Fast 仅读取指定接口的 UP 状态与 IPv4 地址（不查询路由表、DNS 或注册表，供高频哨兵巡检使用）
func queryInterfaceIPv4Fast(ifIndex uint32) (exists bool, isUp bool, ips []string) {
	if ifIndex == 0 {
		return false, false, nil
	}
	f, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil || f == nil {
		return false, false, nil
	}
	exists = true
	isUp = f.Flags&net.FlagUp != 0
	addrs, err := f.Addrs()
	if err != nil {
		return exists, isUp, nil
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsUnspecified() {
				s := ip4.String()
				if !seen[s] {
					seen[s] = true
					ips = append(ips, s)
				}
			}
		}
	}
	return exists, isUp, ips
}

// snapshotPhysicalIPsFast 轻量生成当前活跃物理网卡的 "ifIndex=ip4" 签名（避免调用全量 EnumerateAdapters）
func snapshotPhysicalIPsFast(pinnedIf uint32) string {
	if pinnedIf > 0 {
		exists, isUp, ips := queryInterfaceIPv4Fast(pinnedIf)
		if !exists || !isUp || len(ips) == 0 {
			return ""
		}
		return fmt.Sprintf("%d=%s", pinnedIf, ips[0])
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, f := range ifaces {
		if f.Index <= 0 || f.Flags&net.FlagLoopback != 0 || f.Flags&net.FlagUp == 0 {
			continue
		}
		mac := ""
		if len(f.HardwareAddr) == 6 {
			mac = strings.ToUpper(f.HardwareAddr.String())
		}
		addrs, err := f.Addrs()
		if err != nil {
			continue
		}
		ip4 := ""
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if a4 := ipn.IP.To4(); a4 != nil && !a4.IsLoopback() && !a4.IsUnspecified() {
					ip4 = a4.String()
					break
				}
			}
		}
		if ip4 == "" {
			continue
		}
		isPhys, isTUN, _ := classifyAdapter(f.Name, f.Name, ip4, mac, 0)
		if !isPhys || isTUN {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d=%s", f.Index, ip4))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
