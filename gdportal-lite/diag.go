package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	appVersion = "2.0.0"

	StateDisconnected  = "disconnected"
	StateConnecting    = "connecting"
	StateConnected     = "connected"
	StateDisconnecting = "disconnecting"
	StateError         = "error"
)

// PhaseTimings 记录各认证阶段毫秒耗时
type PhaseTimings struct {
	DetectMs    int64 `json:"detectMs"`
	ConfigMs    int64 `json:"configMs"`
	NegotiateMs int64 `json:"negotiateMs"`
	TicketMs    int64 `json:"ticketMs"`
	LoginMs     int64 `json:"loginMs"`
	TotalMs     int64 `json:"totalMs"`
}

// LogEntry 为实时脱敏日志条目
type LogEntry struct {
	Seq     uint64 `json:"seq"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// WireEntry 为最近脱敏 HTTP 抓包摘要
type WireEntry struct {
	Seq         uint64 `json:"seq"`
	Time        string `json:"time"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	RTTMs       int64  `json:"rttMs"`
	ErrorCode   string `json:"errorCode"`
	ServerTag   string `json:"serverTag,omitempty"`
	ReqBytes    int    `json:"reqBytes"`
	RespBytes   int    `json:"respBytes"`
	BodyPreview string `json:"bodyPreview,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SessionSnapshot 为当前连接状态与元数据快照 (无任何密码或完整凭据)
type SessionSnapshot struct {
	State          string        `json:"state"`
	Stage          string        `json:"stage"`
	AccountMasked  string        `json:"accountMasked"`
	NICName        string        `json:"nicName"`
	NICIfIndex     uint32        `json:"nicIfIndex"`
	UserIP         string        `json:"userIP"`
	Gateway        string        `json:"gateway"`
	MAC            string        `json:"mac"`
	ACIP           string        `json:"acIP"`
	School         string        `json:"school"`
	Domain         string        `json:"domain"`
	Area           string        `json:"area"`
	PortalNode     string        `json:"portalNode"`
	ClusterServers []string      `json:"clusterServers,omitempty"`
	AlgoID         string        `json:"algoID"`
	AlgoFamily     string        `json:"algoFamily"`
	KeepURL        string        `json:"keepURL"`
	KeepRetry      int           `json:"keepRetry"`
	HelloCount     int           `json:"helloCount"`
	AuthTime       string        `json:"authTime,omitempty"`
	LastHeartbeat  string        `json:"lastHeartbeat,omitempty"`
	LastError      string        `json:"lastError,omitempty"`
	Timings        PhaseTimings  `json:"timings"`
	RedirectHops   []RedirectHop `json:"redirectHops,omitempty"`
	ProxyBypassed  bool          `json:"proxyBypassed"`
	BypassMode     string        `json:"bypassMode"`
}

// DoctorCheck 为网络体检单项检查结果
type DoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "warn", "fail"
	RTTMs  int64  `json:"rttMs,omitempty"`
	Detail string `json:"detail"`
	Advice string `json:"advice,omitempty"`
}

// DoctorReport 为一键网络体检完整结果
type DoctorReport struct {
	GeneratedAt string        `json:"generatedAt"`
	Checks      []DoctorCheck `json:"checks"`
	Adapters    []AdapterInfo `json:"adapters"`
	ProxyEnv    ProxyEnvInfo  `json:"proxyEnv"`
}

type DiagHub struct {
	mu      sync.RWMutex
	seq     atomic.Uint64
	wireSeq atomic.Uint64
	logs    []LogEntry
	wires   []WireEntry
	hops    []RedirectHop
	subs    map[int]chan any
	nextSub int
}

func NewDiagHub() *DiagHub {
	return &DiagHub{
		logs:  make([]LogEntry, 0, 128),
		wires: make([]WireEntry, 0, 64),
		subs:  map[int]chan any{},
	}
}

func (d *DiagHub) Subscribe() (int, <-chan any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.nextSub
	d.nextSub++
	ch := make(chan any, 64)
	d.subs[id] = ch
	return id, ch
}

func (d *DiagHub) Unsubscribe(id int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ch, ok := d.subs[id]; ok {
		delete(d.subs, id)
		close(ch)
	}
}

func (d *DiagHub) broadcastLocked(ev any) {
	for _, ch := range d.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (d *DiagHub) AddLog(level, stage, msg string, secrets ...string) LogEntry {
	entry := LogEntry{
		Seq:     d.seq.Add(1),
		Time:    time.Now().Format("15:04:05.000"),
		Level:   level,
		Stage:   stage,
		Message: SanitizeDiagnosticText(msg, secrets...),
	}
	d.mu.Lock()
	if len(d.logs) >= 500 {
		copy(d.logs, d.logs[1:])
		d.logs[len(d.logs)-1] = entry
	} else {
		d.logs = append(d.logs, entry)
	}
	d.broadcastLocked(map[string]any{"type": "log", "data": entry})
	d.mu.Unlock()
	return entry
}

func (d *DiagHub) AddWire(w WireEntry, secrets ...string) WireEntry {
	w.Seq = d.wireSeq.Add(1)
	if w.Time == "" {
		w.Time = time.Now().Format("15:04:05.000")
	}
	w.URL = SanitizeDiagnosticText(w.URL, secrets...)
	w.BodyPreview = SanitizeDiagnosticText(w.BodyPreview, secrets...)
	w.Error = SanitizeDiagnosticText(w.Error, secrets...)
	d.mu.Lock()
	if len(d.wires) >= 60 {
		copy(d.wires, d.wires[1:])
		d.wires[len(d.wires)-1] = w
	} else {
		d.wires = append(d.wires, w)
	}
	d.broadcastLocked(map[string]any{"type": "wire", "data": w})
	d.mu.Unlock()
	return w
}

func (d *DiagHub) SetHops(hops []RedirectHop) {
	d.mu.Lock()
	d.hops = append([]RedirectHop(nil), hops...)
	d.mu.Unlock()
}

func (d *DiagHub) Hops() []RedirectHop {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]RedirectHop(nil), d.hops...)
}

func (d *DiagHub) Logs() []LogEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]LogEntry(nil), d.logs...)
}

func (d *DiagHub) Wires() []WireEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]WireEntry(nil), d.wires...)
}

func (d *DiagHub) Clear() {
	d.mu.Lock()
	d.logs = d.logs[:0]
	d.wires = d.wires[:0]
	d.mu.Unlock()
}

func (d *DiagHub) BroadcastState(snap SessionSnapshot) {
	d.mu.RLock()
	d.broadcastLocked(map[string]any{"type": "state", "data": snap})
	d.mu.RUnlock()
}

// MaskAccount 彻底隐藏手机号/学号凭据（不泄露任何数字或前后缀）
func MaskAccount(u string) string {
	if strings.TrimSpace(u) == "" {
		return ""
	}
	return "<REDACTED>"
}

var (
	sanitizePasswdKVRe  = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']?([^\s"'&,;]+)`)
	sanitizeUserIDXMLRe = regexp.MustCompile(`(?is)(<userid>)[^<]*(</userid>)`)
	sanitizeAccountKVRe = regexp.MustCompile(`(?i)\b(userid|account|phone|mobile)\s*[:=]\s*["']?([^\s"'&,;]+)`)
	sanitizeCookieRe    = regexp.MustCompile(`(?im)((?:set-)?cookie\s*:\s*)([^\r\n]+)`)
	sanitizeTicketXMLRe = regexp.MustCompile(`(?is)(<ticket>)([^<]{6})[^<]*(</ticket>)`)
	sanitizeTicketKVRe  = regexp.MustCompile(`(?i)(ticket["'\s:=]+)([0-9a-fA-F]{6})[0-9a-fA-F]{10,}`)
	sanitizePayloadKey  = regexp.MustCompile(`001[@A-Za-z][0-9a-fA-F]{32,}\$`)
	sanitizePhoneRe     = regexp.MustCompile(`\b1[3-9]\d{9}\b`)

	issueTicketXMLRe = regexp.MustCompile(`(?is)(<ticket>)[^<]*(</ticket>)`)
	issueTicketKVRe  = regexp.MustCompile(`(?i)\b(ticket["'\s:=]+)[0-9a-fA-F*]{6,}`)
	issueMACRe       = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
	issueNetIDRe     = regexp.MustCompile(`\[[0-9a-fA-F]{8,}\]`)
	issueParamIPRe   = regexp.MustCompile(`(?i)\b(wlanuserip|wlanacip|wlanacname|userip|nasip|acip|basip)=([^&\s"')]+)`)
	issueSchoolKVRe  = regexp.MustCompile(`(?i)\b(schoolid|school_id|school|cdc-schoolid)(\s*[:=]\s*["']?)([^"'\s&,)}\]]+)(["']?)`)
	issueSchoolZHRe  = regexp.MustCompile(`(学校(?:\s*ID)?)(\s*[:=：]\s*["']?)([^"'\s&,)}\]]+)(["']?)`)
	issueDomainKVRe  = regexp.MustCompile(`(?i)\b(domain|cdc-domain)(\s*[:=]\s*["']?)([^"'\s&,)}\]]+)(["']?)`)
	issueDomainZHRe  = regexp.MustCompile(`(域名)(\s*[:=：]\s*["']?)([^"'\s&,)}\]]+)(["']?)`)
	issueAreaKVRe    = regexp.MustCompile(`(?i)\b(areacode|area|cdc-area)(\s*[:=]\s*["']?)([^"'\s&,)}\]]+)(["']?)`)
	issueAreaZHRe    = regexp.MustCompile(`(区号|地区)(\s*[:=：]\s*["']?)([^"'\s&,)}\]]+)(["']?)`)
	issueIPv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

var issueAllowedIPs = map[string]bool{
	"127.0.0.1":       true,
	"0.0.0.0":         true,
	"27.159.75.27":    true,
	"223.5.5.5":       true,
	"114.114.114.114": true,
	"119.29.29.29":    true,
	"8.8.8.8":         true,
	"1.1.1.1":         true,
	"202.96.128.86":   true,
	"202.96.128.166":  true,
	"202.96.134.133":  true,
	"202.96.128.68":   true,
	"125.88.59.131":   true,
	"61.140.12.23":    true,
}

func redactIssueIPv4(s string) string {
	if s == "" {
		return ""
	}
	return issueIPv4Re.ReplaceAllStringFunc(s, func(tok string) string {
		ip := net.ParseIP(tok)
		if ip == nil {
			return tok
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return tok
		}
		canonical := ip4.String()
		if issueAllowedIPs[canonical] {
			return tok
		}
		if isFakeIP(ip4) {
			return "198.18.x.x(Fake-IP)"
		}
		if ip4.IsPrivate() || ip4.IsLinkLocalUnicast() {
			return "<LAN_IP>"
		}
		return "<IP_REDACTED>"
	})
}

// SanitizeDiagnosticText 对日志、HTTP 抓包和 Issue 报告内容执行严格隐私脱敏
func SanitizeDiagnosticText(text string, secrets ...string) string {
	if text == "" {
		return ""
	}
	out := redactPasswdRe.ReplaceAllString(text, "<passwd>***</passwd>")
	out = sanitizePasswdKVRe.ReplaceAllString(out, "$1=***")
	out = sanitizeUserIDXMLRe.ReplaceAllString(out, "${1}<REDACTED>${2}")
	out = sanitizeAccountKVRe.ReplaceAllString(out, "$1=<REDACTED>")
	out = sanitizeCookieRe.ReplaceAllString(out, "$1<REDACTED>")
	out = sanitizeTicketXMLRe.ReplaceAllString(out, "${1}${2}***${3}")
	out = sanitizeTicketKVRe.ReplaceAllString(out, "${1}${2}***")
	out = sanitizePayloadKey.ReplaceAllString(out, "001@<KEYHEX_REDACTED>$")
	out = sanitizePhoneRe.ReplaceAllString(out, "<PHONE_REDACTED>")
	for _, sec := range secrets {
		sec = strings.TrimSpace(sec)
		if len(sec) >= 3 {
			out = strings.ReplaceAll(out, sec, "***")
		}
	}
	return out
}

// SanitizeIssueText 对对外导出的 GitHub Issue 报告/JSON 执行零泄露深度脱敏（屏蔽手机号/学校/域名/区号/MAC/主机名/校园网IP）
func SanitizeIssueText(text string, snap SessionSnapshot, secrets ...string) string {
	if text == "" {
		return ""
	}
	out := SanitizeDiagnosticText(text, secrets...)
	out = issueTicketXMLRe.ReplaceAllString(out, "${1}<TICKET_REDACTED>${2}")
	out = issueTicketKVRe.ReplaceAllString(out, "${1}<TICKET_REDACTED>")
	out = issueMACRe.ReplaceAllString(out, "<MAC_REDACTED>")
	out = issueNetIDRe.ReplaceAllString(out, "[<NETID_REDACTED>]")
	out = issueParamIPRe.ReplaceAllString(out, "$1=<IP_REDACTED>")
	out = issueSchoolKVRe.ReplaceAllString(out, "${1}${2}<SCHOOL_REDACTED>${4}")
	out = issueSchoolZHRe.ReplaceAllString(out, "${1}${2}<SCHOOL_REDACTED>${4}")
	out = issueDomainKVRe.ReplaceAllString(out, "${1}${2}<DOMAIN_REDACTED>${4}")
	out = issueDomainZHRe.ReplaceAllString(out, "${1}${2}<DOMAIN_REDACTED>${4}")
	out = issueAreaKVRe.ReplaceAllString(out, "${1}${2}<AREA_REDACTED>${4}")
	out = issueAreaZHRe.ReplaceAllString(out, "${1}${2}<AREA_REDACTED>${4}")

	if dm := strings.TrimSpace(snap.Domain); len(dm) >= 2 {
		low := strings.ToLower(dm)
		if low != "true" && low != "false" && low != "null" && low != "none" && low != "http" {
			if re, err := regexp.Compile(`(?i)(^|[^a-z0-9_])` + regexp.QuoteMeta(dm) + `([^a-z0-9_]|$)`); err == nil {
				out = re.ReplaceAllString(out, "${1}<DOMAIN_REDACTED>${2}")
			}
		}
	}
	if ar := strings.TrimSpace(snap.Area); len(ar) >= 3 {
		if re, err := regexp.Compile(`(^|[^0-9])` + regexp.QuoteMeta(ar) + `([^0-9]|$)`); err == nil {
			out = re.ReplaceAllString(out, "${1}<AREA_REDACTED>${2}")
		}
	}
	if hn, err := os.Hostname(); err == nil {
		hn = strings.TrimSpace(hn)
		if len(hn) >= 3 {
			if re, err2 := regexp.Compile(`(?i)(^|[^a-z0-9_-])` + regexp.QuoteMeta(hn) + `([^a-z0-9_-]|$)`); err2 == nil {
				out = re.ReplaceAllString(out, "${1}<HOST_REDACTED>${2}")
			}
		}
	}
	return redactIssueIPv4(out)
}

// RunNetworkDoctor 在不干扰已有在线会话的前提下，使用 IP_UNICAST_IF 物理直连链路做全项网络体检
func RunNetworkDoctor(ctx context.Context, pinnedIfIndex uint32) DoctorReport {
	adapters := EnumerateAdapters()
	proxyEnv := DetectProxyEnv(adapters)
	var checks []DoctorCheck

	// 1. 选出主物理网卡
	var phys *AdapterInfo
	if pinnedIfIndex > 0 {
		if a, ok := findAdapterByIndex(adapters, pinnedIfIndex); ok {
			phys = &a
		}
	}
	if phys == nil {
		for i := range adapters {
			a := adapters[i]
			if a.IsPhysical && a.IsUp && a.IP4 != "" {
				if phys == nil || (a.HasDefaultRoute && (!phys.HasDefaultRoute || a.DefaultMetric < phys.DefaultMetric)) {
					aa := a
					phys = &aa
				}
			}
		}
	}
	if phys == nil {
		checks = append(checks, DoctorCheck{
			Name:   "物理网卡检测",
			Status: "fail",
			Detail: "未检测到已连接且分配了 IPv4 的物理有线/无线网卡",
			Advice: "请先连接校园网 Wi-Fi 或插入网线并确认已获取 10.x/172.x 内网 IP",
		})
		return DoctorReport{
			GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
			Checks:      checks,
			Adapters:    adapters,
			ProxyEnv:    proxyEnv,
		}
	}

	nicDetail := fmt.Sprintf("%s (%s) IP=%s 网关=%s DNS=%s",
		phys.Name, phys.TypeLabel, phys.IP4, emptyFallback(phys.Gateway, "未知"), strings.Join(phys.DNSServers, ", "))
	if phys.CustomStaticDNS {
		if len(phys.DHCPDNSServers) > 0 {
			nicDetail += " (检测到自定义静态 DNS，已找回 DHCP DNS: " + strings.Join(phys.DHCPDNSServers, ", ") + ")"
		} else {
			nicDetail += " (检测到自定义静态 DNS，已启用电信多线并发旁路)"
		}
	}
	checks = append(checks, DoctorCheck{
		Name:   "物理出口网卡",
		Status: "pass",
		Detail: nicDetail,
	})

	// 2. TUN 与代理绕过检查
	if proxyEnv.TUNActive || proxyEnv.SystemProxyOn || len(proxyEnv.EnvProxyVars) > 0 {
		parts := []string{}
		if len(proxyEnv.TUNAdapters) > 0 {
			parts = append(parts, "TUN网卡: "+strings.Join(proxyEnv.TUNAdapters, ", "))
		}
		if proxyEnv.SplitRoutes {
			parts = append(parts, "存在 0.0.0.0/1 代理接管路由")
		}
		if proxyEnv.SystemProxyOn {
			parts = append(parts, "系统代理: "+proxyEnv.SystemProxyAddr)
		}
		if len(proxyEnv.EnvProxyVars) > 0 {
			parts = append(parts, "环境变量: "+strings.Join(proxyEnv.EnvProxyVars, "; "))
		}
		checks = append(checks, DoctorCheck{
			Name:   "TUN/代理环境兼容性",
			Status: "pass",
			Detail: strings.Join(parts, " | ") + " → 已启用 IP_UNICAST_IF (ifIndex=" + fmt.Sprintf("%d", phys.IfIndex) + ") 物理直连绕过",
		})
	} else {
		checks = append(checks, DoctorCheck{
			Name:   "TUN/代理环境兼容性",
			Status: "pass",
			Detail: "未检测到活跃 TUN 或系统代理拦截",
		})
	}

	cl := boundClientWithNIC(net.ParseIP(phys.IP4), phys.IfIndex, phys.DNSServers, 4*time.Second, 5*time.Second)
	if tr, ok := cl.Transport.(*http.Transport); ok && tr != nil {
		defer tr.CloseIdleConnections()
	}

	// 3. 物理直连并发 DNS 检查 (支持旁路系统自定义 DNS 与 Fake-IP)
	tDNS := time.Now()
	ips, dnsSrc, dnsErr := resolvePinnedIP4List(ctx, net.ParseIP(phys.IP4), phys.IfIndex, phys.DNSServers, "enet.10000.gd.cn")
	dnsMs := time.Since(tDNS).Milliseconds()
	if dnsErr != nil {
		checks = append(checks, DoctorCheck{
			Name:   "直连 DNS (防劫持/Fake-IP)",
			Status: "warn",
			RTTMs:  dnsMs,
			Detail: fmt.Sprintf("直连 DNS 解析失败 (%v)，但客户端仍可使用内置 IP 后备地址", dnsErr),
			Advice: "若在未认证状态下被 AC 拦截或自定义 DNS 不可达，属正常现象",
		})
	} else if dnsSrc == "builtin-fallback" {
		checks = append(checks, DoctorCheck{
			Name:   "直连 DNS (防劫持/Fake-IP)",
			Status: "pass",
			RTTMs:  dnsMs,
			Detail: fmt.Sprintf("物理网卡 DNS 均被拦截/超时，已自动启用内置保底节点 enet.10000.gd.cn → %s", strings.Join(ips, ", ")),
			Advice: "已自动旁路失效 DNS，认证与连接不受影响",
		})
	} else {
		detail := fmt.Sprintf("enet.10000.gd.cn → %s (来源: %s)", strings.Join(ips, ", "), strings.TrimPrefix(dnsSrc, "dns:"))
		if phys.CustomStaticDNS {
			detail += " [已旁路系统自定义 DNS]"
		}
		checks = append(checks, DoctorCheck{
			Name:   "直连 DNS (防劫持/Fake-IP)",
			Status: "pass",
			RTTMs:  dnsMs,
			Detail: detail,
		})
	}

	// 4. 物理直连强制探测 (27.159.75.27)
	tCap := time.Now()
	reqCap, _ := http.NewRequestWithContext(ctx, "GET", "http://27.159.75.27/", nil)
	respCap, capErr := cl.Do(reqCap)
	capMs := time.Since(tCap).Milliseconds()
	if capErr != nil {
		checks = append(checks, DoctorCheck{
			Name:   "物理直连探测 (绕过 TUN)",
			Status: "warn",
			RTTMs:  capMs,
			Detail: fmt.Sprintf("http://27.159.75.27/ 访问异常: %v", capErr),
			Advice: "如果开启了第三方防火墙 (如 COMODO/卡巴斯基)，请放行本程序外发访问",
		})
	} else {
		loc := respCap.Header.Get("Location")
		code := respCap.StatusCode
		respCap.Body.Close()
		stateText := fmt.Sprintf("HTTP %d (当前外网已在线，未被强制认证重定向)", code)
		if loc != "" {
			stateText = fmt.Sprintf("捕获到校园网认证重定向 (%d) → %s", code, portalRoot(loc))
		}
		checks = append(checks, DoctorCheck{
			Name:   "物理直连探测 (绕过 TUN)",
			Status: "pass",
			RTTMs:  capMs,
			Detail: stateText,
		})
	}

	// 5. 广东电信省中心节点可达性
	tDisp := time.Now()
	reqDisp, _ := http.NewRequestWithContext(ctx, "GET", "http://125.88.59.131:10001/?wlanuserip="+phys.IP4, nil)
	respDisp, dispErr := cl.Do(reqDisp)
	dispMs := time.Since(tDisp).Milliseconds()
	if dispErr != nil {
		checks = append(checks, DoctorCheck{
			Name:   "省中心调度节点可达性",
			Status: "warn",
			RTTMs:  dispMs,
			Detail: fmt.Sprintf("125.88.59.131:10001 无响应: %v", dispErr),
		})
	} else {
		sc := respDisp.Header.Get("schoolid")
		dm := respDisp.Header.Get("domain")
		ar := respDisp.Header.Get("area")
		loc := respDisp.Header.Get("Location")
		code := respDisp.StatusCode
		respDisp.Body.Close()
		extra := fmt.Sprintf("HTTP %d", code)
		if sc != "" || dm != "" || ar != "" {
			extra += fmt.Sprintf(" | 自动识别: school=%s domain=%s area=%s", sc, dm, ar)
		}
		if loc != "" {
			extra += " | Portal=" + portalRoot(loc)
		}
		checks = append(checks, DoctorCheck{
			Name:   "省中心调度节点可达性",
			Status: "pass",
			RTTMs:  dispMs,
			Detail: extra,
		})
	}

	return DoctorReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Checks:      checks,
		Adapters:    adapters,
		ProxyEnv:    proxyEnv,
	}
}

func emptyFallback(s, fb string) string {
	if strings.TrimSpace(s) == "" {
		return fb
	}
	return s
}

// BuildIssueMarkdown 生成可直接粘贴到 GitHub Issue 的零隐私泄露诊断报告
func BuildIssueMarkdown(snap SessionSnapshot, proxy ProxyEnvInfo, adapters []AdapterInfo, doctor *DoctorReport, logs []LogEntry, wires []WireEntry, secrets ...string) string {
	var b strings.Builder
	san := func(s string) string {
		return SanitizeIssueText(s, snap, secrets...)
	}
	b.WriteString("## 问题现象\n")
	b.WriteString("<!-- 请在此简述你遇到的问题，例如：无法获取学校参数 / 认证被拒 / 心跳掉线 -->\n\n")

	acctStatus := "未配置"
	if strings.TrimSpace(snap.AccountMasked) != "" {
		acctStatus = "已配置 (已完全隐藏)"
	}
	schoolStatus := "未获取"
	if snap.School != "" || snap.Domain != "" || snap.Area != "" {
		schoolStatus = "已自动/手动识别 (已隐藏)"
	}
	acStatus := "-"
	if strings.TrimSpace(snap.ACIP) != "" {
		acStatus = redactIssueIPv4(snap.ACIP)
	}

	b.WriteString("## 环境与会诊摘要 (已深度脱敏，零隐私泄露)\n")
	b.WriteString("| 项 | 值 |\n|---|---|\n")
	fmt.Fprintf(&b, "| 客户端版本 | gdportal-lite v%s (%s %s/%s) |\n", appVersion, windowsBuild(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "| 连接状态 | `%s` (阶段: `%s`) |\n", snap.State, emptyFallback(snap.Stage, "-"))
	fmt.Fprintf(&b, "| 账号凭据 | `%s` |\n", acctStatus)
	fmt.Fprintf(&b, "| 学校参数 | `%s` |\n", schoolStatus)
	fmt.Fprintf(&b, "| 物理出口网卡 | `%s` (ifIndex=%d IP=`<LAN_IP>`) |\n",
		emptyFallback(san(snap.NICName), "-"), snap.NICIfIndex)
	fmt.Fprintf(&b, "| AC / Portal 节点 | ac=`%s` portalNode=`%s` keepURL=`%s` |\n",
		acStatus, emptyFallback(san(snap.PortalNode), "-"), emptyFallback(san(snap.KeepURL), "-"))
	fmt.Fprintf(&b, "| 算法与耗时 | `%s` (`%s`) | 总计 `%dms` (探测 %d / 配置 %d / 协商 %d / 取票 %d / 登录 %d) |\n",
		emptyFallback(snap.AlgoFamily, "-"), emptyFallback(snap.AlgoID, "-"),
		snap.Timings.TotalMs, snap.Timings.DetectMs, snap.Timings.ConfigMs, snap.Timings.NegotiateMs, snap.Timings.TicketMs, snap.Timings.LoginMs)
	fmt.Fprintf(&b, "| 代理 / TUN 状态 | TUN活跃=`%v` (%s) | 分流路由=`%v` | 系统代理=`%v` |\n",
		proxy.TUNActive, emptyFallback(san(strings.Join(proxy.TUNAdapters, ", ")), "无"), proxy.SplitRoutes, proxy.SystemProxyOn)
	if snap.LastError != "" {
		fmt.Fprintf(&b, "| 最近错误 | `%s` |\n", san(snap.LastError))
	}

	if len(snap.RedirectHops) > 0 {
		b.WriteString("\n## 重定向链 (已脱敏)\n")
		for i, h := range snap.RedirectHops {
			hasSchool := h.School != "" || h.Domain != "" || h.Area != ""
			fmt.Fprintf(&b, "%d. `%s` HTTP=%d (%s, %dms) 含学校参数=`%v` → `%s`\n",
				i+1, san(h.URL), h.Status, h.Kind, h.RTTMs, hasSchool, san(h.Location))
		}
	}

	if len(adapters) > 0 {
		b.WriteString("\n## 网卡快照 (已脱敏)\n")
		for _, a := range adapters {
			fmt.Fprintf(&b, "- [%d] `%s` (%s, physical=%v, tun=%v, up=%v) IP=`%s` GW=`%s`",
				a.IfIndex, san(a.Name), a.TypeLabel, a.IsPhysical, a.IsTUN, a.IsUp,
				emptyFallback(redactIssueIPv4(a.IP4), "-"), emptyFallback(redactIssueIPv4(a.Gateway), "-"))
			if a.TUNReason != "" {
				fmt.Fprintf(&b, " (%s)", san(a.TUNReason))
			}
			b.WriteString("\n")
		}
	}

	if doctor != nil && len(doctor.Checks) > 0 {
		b.WriteString("\n## 网络体检结果 (" + doctor.GeneratedAt + ")\n")
		for _, ck := range doctor.Checks {
			fmt.Fprintf(&b, "- **[%s]** %s (%dms): %s\n", strings.ToUpper(ck.Status), ck.Name, ck.RTTMs, san(ck.Detail))
		}
	}

	if len(wires) > 0 {
		b.WriteString("\n## 最近 HTTP 请求摘要 (已脱敏)\n```text\n")
		start := 0
		if len(wires) > 25 {
			start = len(wires) - 25
		}
		for _, w := range wires[start:] {
			fmt.Fprintf(&b, "%s %s %s -> HTTP=%d EC=%s rtt=%dms tag=%s req=%dB resp=%dB err=%s body=%s\n",
				w.Time, w.Method, san(w.URL),
				w.Status, w.ErrorCode, w.RTTMs, w.ServerTag, w.ReqBytes, w.RespBytes,
				san(w.Error), san(w.BodyPreview))
		}
		b.WriteString("```\n")
	}

	if len(logs) > 0 {
		b.WriteString("\n<details>\n<summary>最近客户端日志 (已脱敏)</summary>\n\n```text\n")
		start := 0
		if len(logs) > 80 {
			start = len(logs) - 80
		}
		for _, l := range logs[start:] {
			fmt.Fprintf(&b, "%s [%s/%s] %s\n", l.Time, l.Level, l.Stage, san(l.Message))
		}
		b.WriteString("```\n</details>\n")
	}
	return b.String()
}

func redactFlag(v string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return "<REDACTED>"
}

// BuildIssueJSON 生成零隐私泄露的结构化脱敏诊断 JSON
func BuildIssueJSON(snap SessionSnapshot, proxy ProxyEnvInfo, adapters []AdapterInfo, doctor *DoctorReport, logs []LogEntry, wires []WireEntry, secrets ...string) []byte {
	san := func(s string) string {
		return SanitizeIssueText(s, snap, secrets...)
	}

	cleanSnap := snap
	cleanSnap.AccountMasked = redactFlag(snap.AccountMasked)
	cleanSnap.NICName = san(snap.NICName)
	cleanSnap.UserIP = redactIssueIPv4(snap.UserIP)
	cleanSnap.Gateway = redactIssueIPv4(snap.Gateway)
	if strings.TrimSpace(snap.MAC) != "" {
		cleanSnap.MAC = "<MAC_REDACTED>"
	}
	cleanSnap.ACIP = redactIssueIPv4(snap.ACIP)
	cleanSnap.School = redactFlag(snap.School)
	cleanSnap.Domain = redactFlag(snap.Domain)
	cleanSnap.Area = redactFlag(snap.Area)
	cleanSnap.PortalNode = san(snap.PortalNode)
	cleanSnap.KeepURL = san(snap.KeepURL)
	cleanSnap.LastError = san(snap.LastError)
	if len(snap.ClusterServers) > 0 {
		cs := make([]string, len(snap.ClusterServers))
		for i, s := range snap.ClusterServers {
			cs[i] = san(s)
		}
		cleanSnap.ClusterServers = cs
	}
	if len(snap.RedirectHops) > 0 {
		hops := make([]RedirectHop, len(snap.RedirectHops))
		for i, h := range snap.RedirectHops {
			hops[i] = h
			hops[i].URL = san(h.URL)
			hops[i].Location = san(h.Location)
			hops[i].School = redactFlag(h.School)
			hops[i].Domain = redactFlag(h.Domain)
			hops[i].Area = redactFlag(h.Area)
		}
		cleanSnap.RedirectHops = hops
	}

	cleanAdapters := make([]AdapterInfo, len(adapters))
	for i, a := range adapters {
		ca := a
		ca.Name = san(a.Name)
		ca.Description = san(a.Description)
		ca.IP4 = redactIssueIPv4(a.IP4)
		ca.Gateway = redactIssueIPv4(a.Gateway)
		ca.TUNReason = san(a.TUNReason)
		if strings.TrimSpace(a.MAC) != "" {
			ca.MAC = "<MAC_REDACTED>"
		}
		if len(a.DNSServers) > 0 {
			ds := make([]string, len(a.DNSServers))
			for j, d := range a.DNSServers {
				ds[j] = redactIssueIPv4(d)
			}
			ca.DNSServers = ds
		}
		if len(a.DHCPDNSServers) > 0 {
			ds := make([]string, len(a.DHCPDNSServers))
			for j, d := range a.DHCPDNSServers {
				ds[j] = redactIssueIPv4(d)
			}
			ca.DHCPDNSServers = ds
		}
		cleanAdapters[i] = ca
	}

	cleanProxy := proxy
	cleanProxy.SystemProxyAddr = redactIssueIPv4(proxy.SystemProxyAddr)
	cleanProxy.BypassMode = san(proxy.BypassMode)
	if len(proxy.EnvProxyVars) > 0 {
		ev := make([]string, len(proxy.EnvProxyVars))
		for i, v := range proxy.EnvProxyVars {
			ev[i] = san(v)
		}
		cleanProxy.EnvProxyVars = ev
	}
	if len(proxy.TUNAdapters) > 0 {
		ta := make([]string, len(proxy.TUNAdapters))
		for i, t := range proxy.TUNAdapters {
			ta[i] = san(t)
		}
		cleanProxy.TUNAdapters = ta
	}
	cleanSnap.BypassMode = cleanProxy.BypassMode

	var cleanDoc *DoctorReport
	if doctor != nil {
		dcp := *doctor
		if len(doctor.Checks) > 0 {
			cks := make([]DoctorCheck, len(doctor.Checks))
			for i, ck := range doctor.Checks {
				cks[i] = ck
				cks[i].Detail = san(ck.Detail)
				cks[i].Advice = san(ck.Advice)
			}
			dcp.Checks = cks
		}
		dcp.Adapters = cleanAdapters
		dcp.ProxyEnv = cleanProxy
		cleanDoc = &dcp
	}

	cleanWires := make([]WireEntry, len(wires))
	for i, w := range wires {
		cw := w
		cw.URL = san(w.URL)
		cw.ServerTag = san(w.ServerTag)
		cw.BodyPreview = san(w.BodyPreview)
		cw.Error = san(w.Error)
		cleanWires[i] = cw
	}

	cleanLogs := make([]LogEntry, len(logs))
	for i, l := range logs {
		cl := l
		cl.Message = san(l.Message)
		cleanLogs[i] = cl
	}

	payload := map[string]any{
		"generatedAt": time.Now().Format(time.RFC3339),
		"version":     appVersion,
		"os":          san(windowsBuild()),
		"arch":        runtime.GOOS + "/" + runtime.GOARCH,
		"session":     cleanSnap,
		"proxyEnv":    cleanProxy,
		"adapters":    cleanAdapters,
		"doctor":      cleanDoc,
		"wires":       cleanWires,
		"logs":        cleanLogs,
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	return raw
}
