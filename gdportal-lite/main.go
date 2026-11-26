// gdportal-lite —— 广东电信天翼校园网(GD Portal)轻量认证客户端
// 逆向自 Chinatelecom_GDPortal V3.5.68 (InnerVer 1068) PC 客户端
// 仅保留认证部分: 检测重定向 -> index.cgi(EConfig) -> ticket.cgi(算法协商+取票) -> state.cgi -> auth.cgi(登录) -> keep.cgi(心跳)
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	gdcp "gdportal-lite/cipher"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ulikunitz/xz/lzma"
)

const UserAgent = "CCTP/WinSVR5/1068" // PC 客户端 UA（安卓端为 CCTP/android64_vpn/2093）

var (
	debugMode      atomic.Bool
	queryStateMode atomic.Bool
	daemonMode     atomic.Bool
)

func isDebugMode() bool        { return debugMode.Load() }
func setDebugMode(v bool)      { debugMode.Store(v) }
func isQueryStateMode() bool   { return queryStateMode.Load() }
func setQueryStateMode(v bool) { queryStateMode.Store(v) }
func isDaemonMode() bool       { return daemonMode.Load() }
func setDaemonMode(v bool)     { daemonMode.Store(v) }

var (
	ticketRetryMaxCycles = 3
	ticketRetryBudget    = 30 * time.Second
	ticketRetryBackoffs  = []time.Duration{2 * time.Second, 4 * time.Second}
)

// ---------------- 静态算法（统一委托 cipher 子包） ----------------

type Cipher interface {
	Encrypt(plain []byte) (string, error) // 返回大写 hex
	Decrypt(hexStr string) ([]byte, error)
}

const (
	AlgoAesEcb = "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4"
	AlgoAesCbc = "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E"
	AlgoXTea   = "B3047D4E-67DF-4864-A6A5-DF9B9E525C79"
	AlgoXTeaIv = "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1"
	AlgoSm4Cbc = "F3974434-C0DD-4C20-9E87-DDB6814A1C48" // 已内置 (cipher 子包)
	AlgoZUC    = "B809531F-0007-4B5B-923B-4BD560398113" // 已内置 (cipher 子包)
	AlgoDesEcb = "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5" // 已内置 (cipher 子包)
	AlgoDesCbc = "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81" // 已内置 (cipher 子包)
	AlgoSm4Ecb = "ED382482-F72C-4C41-A76D-28EEA0F1F2AF" // 已内置 (cipher 子包)
	zeroAlgoID = "00000000-0000-0000-0000-000000000000"
)

// gmsmCipher 适配 cipher 子包 (Encrypt/Decrypt 已直接处理大写 hex 编解码) 到本地 Cipher 接口
type gmsmCipher struct {
	enc func([]byte) ([]byte, error)
	dec func([]byte) ([]byte, error)
}

func (w *gmsmCipher) Encrypt(p []byte) (string, error) {
	x, err := w.enc(p)
	if err != nil {
		return "", err
	}
	return string(x), nil
}

func (w *gmsmCipher) Decrypt(h string) ([]byte, error) {
	return w.dec([]byte(h))
}

// decodeStaticTicket 解析静态模式取票响应 (Esurfing-go DecodeAlgoID 同款 len-prefixed 格式):
// data[3]=key长度 → key → 1字节 algoid 长度(0x24=36) → algoid(UUID)。仅当 algoid 命中静态表才算成功。
func decodeStaticTicket(data []byte) (Cipher, string, error) {
	if len(data) < 8 {
		return nil, "", errors.New("静态响应过短")
	}
	algoid, _, err := DecodeAlgoID(data)
	if err != nil {
		return nil, "", err
	}
	ci, err := newCipher(algoid)
	if err != nil {
		return nil, "", err
	}
	return ci, algoid, nil
}

func newCipher(algoID string) (Cipher, error) {
	c := gdcp.NewCipher(algoID)
	if c == nil {
		return nil, fmt.Errorf("未内置的静态算法: %s", algoID)
	}
	return &gmsmCipher{c.Encrypt, c.Decrypt}, nil
}

func trimZero(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// ---------------- 工具 ----------------

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

func randMAC() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	b[0] = (b[0] & 0xfe) | 0x02
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

func randUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return strings.ToLower(fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))
}

// DecodeAlgoID 解析服务端算法载荷:
// 标准静态格式: [3字节魔数][1B keyLen][key][1B idLen=0x24(36)][36B UUID algoId]
// 兼容带显式 '$' 分隔的载荷: [3B][1B keyLen][key]['$'][1B idLen][algoId]
func DecodeAlgoID(data []byte) (algoID string, key string, err error) {
	if len(data) < 8 {
		return "", "", errors.New("载荷过短")
	}
	keyLen := int(data[3])
	pos := 4
	if pos+keyLen >= len(data) {
		return "", "", errors.New("key 越界")
	}
	key = string(data[pos : pos+keyLen])
	pos += keyLen

	// 优先按真实 len-prefixed 格式解析 (UUID 长度 36 == 0x24 == '$')
	if pos+1+36 <= len(data) && int(data[pos]) == 36 {
		cand := string(data[pos+1 : pos+1+36])
		if uuidRe.MatchString(cand) {
			return cand, key, nil
		}
	}
	// 次选: '$' 分隔符 + 1B idLen + algoId
	if data[pos] == '$' && pos+2 < len(data) {
		idLen := int(data[pos+1])
		if idLen == 36 && pos+2+idLen <= len(data) {
			cand := string(data[pos+2 : pos+2+idLen])
			if uuidRe.MatchString(cand) {
				return cand, key, nil
			}
		}
	}
	return "", "", errors.New("静态响应 algoid 长度或格式异常")
}

// ---------------- 客户端 ----------------

type Client struct {
	mu                   sync.Mutex
	user, pass           string
	school, domain, area string
	// 命令行或手动覆盖显式指定的学校信息 (优先级最高, 不被服务器下发覆盖)
	cmdSchool, cmdDomain, cmdArea                  string
	portalPage                                     string // AC 第二跳 302 的 Location (portal 页面地址, 备用认证主机候选)
	portalNode                                     string // 重定向参数里的 portal_node (省调度中心/认证节点)
	clusterServers                                 []string
	clientID                                       string
	mac, hostName, ostag                           string
	userIP, acIP                                   string
	srcIP                                          net.IP // 校园网接口源 IP (portal 校验源 IP 与会话一致性, 双出口必须绑定)
	srcIfIndex                                     uint32
	pinnedIfIndex                                  uint32
	nicName, nicGateway                            string
	nicDNS                                         []string
	algoID, algoFamily                             string
	cipher                                         Cipher
	ticket                                         string
	ticketURL, authURL, stateURL, keepURL, termURL string
	econfigHost, preflightHost                     string
	cachedGWKey, cachedGWIP                        string
	keepRetry                                      int
	helloCount                                     int       // keep 次数 (官方 excheck-args 的 hello 计数)
	authTime                                       time.Time // 认证完成时刻 (官方 excheck-args 的 conn 秒数基准)
	lastHeartbeat                                  time.Time
	connState, connStage, lastError                string
	lastTimings                                    PhaseTimings
	diag                                           *DiagHub
	onState                                        func(SessionSnapshot)
	onAuthSuccess                                  func()
	http                                           *http.Client
	runCtx                                         context.Context
	detached                                       atomic.Bool
	deadPortals                                    map[string]bool
	watchdogURL                                    string        // 可覆盖的保活哨兵 URL (默认 http://27.159.75.27/)
	watchdogInterval                               time.Duration // 在线哨兵探测间隔 (默认 8s)
}

func (c *Client) activeCtx() context.Context {
	c.mu.Lock()
	ctx := c.runCtx
	c.mu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (c *Client) getHTTPClient() *http.Client {
	c.mu.Lock()
	cl := c.http
	c.mu.Unlock()
	return cl
}

func (c *Client) getNICBind() (net.IP, uint32, []string) {
	c.mu.Lock()
	srcIP := append(net.IP(nil), c.srcIP...)
	ifIdx := c.srcIfIndex
	dns := append([]string(nil), c.nicDNS...)
	c.mu.Unlock()
	return srcIP, ifIdx, dns
}

func (c *Client) getPinnedIfIndex() uint32 {
	c.mu.Lock()
	idx := c.pinnedIfIndex
	c.mu.Unlock()
	return idx
}

func (c *Client) setPinnedIfIndex(idx uint32) {
	c.mu.Lock()
	c.pinnedIfIndex = idx
	c.mu.Unlock()
}

func (c *Client) getSessionIPs() (string, string) {
	c.mu.Lock()
	uip, aip := c.userIP, c.acIP
	c.mu.Unlock()
	return uip, aip
}

func (c *Client) setSessionIPs(userIP, acIP string, onlyIfEmpty bool) {
	c.mu.Lock()
	if userIP != "" && (!onlyIfEmpty || c.userIP == "") {
		c.userIP = userIP
	}
	if acIP != "" && (!onlyIfEmpty || c.acIP == "") {
		c.acIP = acIP
	}
	c.mu.Unlock()
}

func (c *Client) getPortalNode() string {
	c.mu.Lock()
	p := c.portalNode
	c.mu.Unlock()
	return p
}

func (c *Client) setPortalNode(node string, onlyIfEmpty bool) {
	if node == "" {
		return
	}
	root := portalRoot(node)
	c.mu.Lock()
	if !onlyIfEmpty || c.portalNode == "" {
		c.portalNode = root
	}
	c.mu.Unlock()
}

func (c *Client) getSchoolInfo() (string, string, string) {
	c.mu.Lock()
	sc, dm, ar := c.school, c.domain, c.area
	c.mu.Unlock()
	return sc, dm, ar
}

func (c *Client) setPortalPage(u string, onlyIfEmpty bool) {
	if u == "" {
		return
	}
	c.mu.Lock()
	if !onlyIfEmpty || c.portalPage == "" {
		c.portalPage = u
	}
	c.mu.Unlock()
}

func (c *Client) addClusterServers(servers ...string) {
	c.mu.Lock()
	for _, s := range servers {
		if s != "" {
			c.clusterServers = appendUniqueStr(c.clusterServers, s)
		}
	}
	c.mu.Unlock()
}

func (c *Client) setEConfigResult(econfigHost, portalPage, ticketURL, authURL, stateURL string, clusters []string) {
	c.mu.Lock()
	if econfigHost != "" {
		c.econfigHost = econfigHost
	}
	if portalPage != "" {
		c.portalPage = portalPage
		c.clusterServers = appendUniqueStr(c.clusterServers, portalRoot(portalPage))
	}
	for _, cs := range clusters {
		if cs != "" {
			c.clusterServers = appendUniqueStr(c.clusterServers, cs)
		}
	}
	if ticketURL != "" {
		c.ticketURL = ticketURL
	}
	if authURL != "" {
		c.authURL = authURL
	}
	if stateURL != "" {
		c.stateURL = stateURL
	}
	c.mu.Unlock()
}

func (c *Client) getEndpointURLs() (ticketURL, authURL, stateURL, keepURL, termURL string) {
	c.mu.Lock()
	ticketURL = c.ticketURL
	authURL = c.authURL
	stateURL = c.stateURL
	keepURL = c.keepURL
	termURL = c.termURL
	c.mu.Unlock()
	return
}

func (c *Client) logf(level, stage, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if c.diag != nil {
		c.diag.AddLog(level, stage, msg, c.pass, c.user)
	}
	if !isDaemonMode() {
		if level == "ERROR" {
			fmt.Fprintln(os.Stderr, msg)
		} else {
			fmt.Println(msg)
		}
	}
}

func (c *Client) Snapshot() SessionSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hops []RedirectHop
	if c.diag != nil {
		hops = c.diag.Hops()
	}
	authT := ""
	if !c.authTime.IsZero() {
		authT = c.authTime.Format("2006-01-02 15:04:05")
	}
	lastHB := ""
	if !c.lastHeartbeat.IsZero() {
		lastHB = c.lastHeartbeat.Format("15:04:05")
	}
	st := c.connState
	if st == "" {
		st = StateDisconnected
	}
	return SessionSnapshot{
		State:          st,
		Stage:          c.connStage,
		AccountMasked:  MaskAccount(c.user),
		NICName:        c.nicName,
		NICIfIndex:     c.srcIfIndex,
		UserIP:         c.userIP,
		Gateway:        c.nicGateway,
		MAC:            c.mac,
		ACIP:           c.acIP,
		School:         c.school,
		Domain:         c.domain,
		Area:           c.area,
		PortalNode:     c.portalNode,
		ClusterServers: append([]string(nil), c.clusterServers...),
		AlgoID:         c.algoID,
		AlgoFamily:     c.algoFamily,
		KeepURL:        c.keepURL,
		KeepRetry:      c.keepRetry,
		HelloCount:     c.helloCount,
		AuthTime:       authT,
		LastHeartbeat:  lastHB,
		LastError:      c.lastError,
		Timings:        c.lastTimings,
		RedirectHops:   hops,
		ProxyBypassed:  c.srcIfIndex > 0 || c.srcIP != nil,
	}
}

func (c *Client) setState(state, stage, errMsg string) {
	if c.detached.Load() {
		return
	}
	c.mu.Lock()
	c.connState = state
	c.connStage = stage
	if errMsg != "" {
		c.lastError = SanitizeDiagnosticText(errMsg, c.pass, c.user)
	} else if state == StateConnected || state == StateDisconnected {
		c.lastError = ""
	}
	cb := c.onState
	dg := c.diag
	c.mu.Unlock()
	if dg != nil || cb != nil {
		snap := c.Snapshot()
		if dg != nil {
			dg.BroadcastState(snap)
		}
		if cb != nil {
			cb(snap)
		}
	}
}

// 真实主机特征: 机器名 / 物理网卡 MAC / Windows Build 号
// (服务端按这些字段识别终端类型; 随机值会被归为"移动终端")
func localHostName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "DESKTOP-" + randHex(4)
}

func isValidMAC(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	// 忽略 00:00:00 前缀虚拟/伪网卡
	return !(hw[0] == 0 && hw[1] == 0 && hw[2] == 0)
}

func localMAC() string {
	if ifs, err := net.Interfaces(); err == nil {
		for _, f := range ifs {
			if f.Flags&net.FlagLoopback != 0 || f.Flags&net.FlagUp == 0 || !isValidMAC(f.HardwareAddr) {
				continue
			}
			return strings.ToUpper(f.HardwareAddr.String())
		}
	}
	return randMAC()
}

const portalProbeIP = "125.88.59.131"

func (c *Client) gwIP() string {
	c.mu.Lock()
	nicGW := c.nicGateway
	turl := c.ticketURL
	uip, aip := c.userIP, c.acIP
	cachedKey, cachedGW := c.cachedGWKey, c.cachedGWIP
	c.mu.Unlock()

	if nicGW != "" {
		return nicGW
	}
	targetHost := ""
	if turl != "" {
		targetHost = hostOf(turl)
		if hostOnly, _, err := net.SplitHostPort(targetHost); err == nil {
			targetHost = hostOnly
		}
	}
	cacheKey := uip + "|" + targetHost + "|" + aip
	if cachedKey == cacheKey && cachedGW != "" {
		return cachedGW
	}
	dst := net.ParseIP(targetHost)
	if dst == nil {
		dst = net.ParseIP(aip)
	}
	if dst == nil {
		dst = net.ParseIP(portalProbeIP)
	}
	if dst == nil {
		dst = net.IPv4(8, 8, 8, 8)
	}
	src := net.ParseIP(uip)
	if src == nil || src.To4() == nil || dst.To4() == nil {
		return aip
	}
	res := platformBestRouteGW(dst, src)
	if res == "" {
		return aip
	}
	c.mu.Lock()
	c.cachedGWKey = cacheKey
	c.cachedGWIP = res
	c.mu.Unlock()
	return res
}

func NewClient(user, pass, school, domain, area string) *Client {
	return &Client{
		user: user, pass: pass, school: school, domain: domain, area: area,
		cmdSchool: school, cmdDomain: domain, cmdArea: area,
		clientID:  randUUID(),
		mac:       strings.ReplaceAll(localMAC(), ":", "-"),
		hostName:  strings.ToUpper(localHostName()), ostag: windowsBuild(),
		algoID:    zeroAlgoID,
		connState: StateDisconnected,
		diag:      NewDiagHub(),
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:              nil,
				DisableCompression: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Client) doWithClient(cl *http.Client, req *http.Request, connHdr string) (*http.Response, []byte, error) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*")
	req.Header.Set("Connection", connHdr)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
	return resp, body, err
}

func (c *Client) doWithConn(req *http.Request, connHdr string) (*http.Response, []byte, error) {
	return c.doWithClient(c.getHTTPClient(), req, connHdr)
}

func (c *Client) fastConfigClient() (*http.Client, func()) {
	c.mu.Lock()
	srcIP := append(net.IP(nil), c.srcIP...)
	ifIdx := c.srcIfIndex
	dns := append([]string(nil), c.nicDNS...)
	base := c.http
	c.mu.Unlock()
	if srcIP == nil && ifIdx == 0 && base != nil && base.Transport != nil {
		return &http.Client{
			Transport:     base.Transport,
			Timeout:       3500 * time.Millisecond,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}, func() {}
	}
	cl := boundClientWithNIC(srcIP, ifIdx, dns, 2*time.Second, 3500*time.Millisecond)
	return cl, func() {
		if tr, ok := cl.Transport.(*http.Transport); ok && tr != nil {
			tr.CloseIdleConnections()
		}
	}
}

func (c *Client) do(req *http.Request) (*http.Response, []byte, error) {
	return c.doWithConn(req, "close")
}

func (c *Client) doKeepAlive(req *http.Request) (*http.Response, []byte, error) {
	return c.doWithConn(req, "keep-alive")
}

// boundClient 生成绑定指定源 IP 的 HTTP 客户端 (portal 校验请求源 IP 与 wlanuserip 一致)
func boundClient(ip net.IP) *http.Client {
	return boundClientWithNIC(ip, 0, nil, 10*time.Second, 30*time.Second)
}

func boundClientWithTimeout(ip net.IP, dialTimeout, totalTimeout time.Duration) *http.Client {
	return boundClientWithNIC(ip, 0, nil, dialTimeout, totalTimeout)
}

// ifaceMACByIP 找到持有指定 IPv4 的接口, 返回其硬件地址 (连字符大写格式, 与官方 XML 一致)
func ifaceMACByIP(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, f := range ifaces {
		addrs, err := f.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == ip && isValidMAC(f.HardwareAddr) {
				return strings.ToUpper(f.HardwareAddr.String())
			}
		}
	}
	return ""
}

func (c *Client) setHTTPClient(cl *http.Client) {
	c.mu.Lock()
	old := c.http
	c.http = cl
	c.mu.Unlock()
	if old != nil {
		if tr, ok := old.Transport.(*http.Transport); ok && tr != nil {
			tr.CloseIdleConnections()
		}
	}
}

type detectCandidate struct {
	ip4 net.IP
	mac string
}

func isCaptivePortalURL(loc string) bool {
	if loc == "" {
		return false
	}
	low := strings.ToLower(loc)
	return strings.Contains(low, "wlanuserip=") ||
		strings.Contains(low, "wlanacip=") ||
		strings.Contains(low, "userip=") ||
		strings.Contains(low, "nasip=") ||
		strings.Contains(low, "/index.cgi") ||
		strings.Contains(low, ":10001") ||
		strings.Contains(low, ":7001")
}

func extractCaptiveRedirect(resp *http.Response, baseURL string) (string, bool) {
	if resp == nil {
		return "", false
	}
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && isCaptivePortalURL(loc) {
		if bu, err := url.Parse(baseURL); err == nil {
			if ru, err2 := bu.Parse(loc); err2 == nil {
				loc = ru.String()
			}
		}
		return loc, true
	}
	if resp.StatusCode == 200 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		if next, _ := extractRedirectFromHTML(string(buf), baseURL); isCaptivePortalURL(next) {
			return next, true
		}
	}
	return "", false
}

// Detect 并发探测物理网络出口，绕过 TUN/VPN 虚拟网卡，找到第一个需要校园网认证的接口。
func (c *Client) Detect() (string, error) {
	return c.DetectContext(context.Background())
}

// DetectContext 支持上下文取消的物理出口探测
func (c *Client) DetectContext(parentCtx context.Context) (string, error) {
	adapters := EnumerateAdapters()
	var cands []AdapterInfo
	pinnedIdx := c.getPinnedIfIndex()
	if pinnedIdx > 0 {
		if a, ok := findAdapterByIndex(adapters, pinnedIdx); ok && a.IsUp && a.IP4 != "" {
			cands = append(cands, a)
		}
	}
	if len(cands) == 0 {
		for _, a := range adapters {
			if a.IsPhysical && a.IsUp && a.IP4 != "" {
				cands = append(cands, a)
			}
		}
	}
	if len(cands) == 0 {
		for _, a := range adapters {
			if !a.IsTUN && a.IsUp && a.IP4 != "" && a.IP4 != "127.0.0.1" {
				cands = append(cands, a)
			}
		}
	}
	if len(cands) == 0 {
		return "", errors.New("未检测到可用的物理网络接口 (已自动排除 TUN/VPN 虚拟网卡)")
	}

	type probeRes struct {
		cand   AdapterInfo
		loc    string
		second bool
	}
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		winner     *probeRes
		online     bool
		onlineCand *AdapterInfo
		onlineOnce sync.Once
		diags      = make(map[string]string, len(cands))
	)

	probeGet := func(cl *http.Client, target string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return nil, err
		}
		return cl.Do(req)
	}

	markOnline := func(cd AdapterInfo) {
		online = true
		if onlineCand == nil {
			cp := cd
			onlineCand = &cp
		}
		onlineOnce.Do(func() {
			time.AfterFunc(600*time.Millisecond, cancel)
		})
	}

	recordWinner := func(cd AdapterInfo, loc string, second bool) {
		mu.Lock()
		if winner == nil {
			winner = &probeRes{cand: cd, loc: loc, second: second}
			cancel()
		}
		mu.Unlock()
	}

	for _, cand := range cands {
		wg.Add(1)
		go func(cd AdapterInfo) {
			defer wg.Done()
			ip4 := net.ParseIP(cd.IP4).To4()
			if ip4 == nil {
				return
			}
			cl := boundClientWithNIC(ip4, cd.IfIndex, cd.DNSServers, 4*time.Second, 5*time.Second)
			if tr, ok := cl.Transport.(*http.Transport); ok && tr != nil {
				defer tr.CloseIdleConnections()
			}

			var innerWG sync.WaitGroup
			innerWG.Add(4)

			// 1) 零 DNS 电信认证探测 IP
			go func() {
				defer innerWG.Done()
				resp, err := probeGet(cl, "http://27.159.75.27/")
				if err != nil {
					return
				}
				loc, ok := extractCaptiveRedirect(resp, "http://27.159.75.27/")
				code := resp.StatusCode
				resp.Body.Close()
				if ok {
					recordWinner(cd, loc, false)
					return
				}
				if code == 200 || code == 204 || code == 403 {
					mu.Lock()
					if _, exists := diags[cd.IP4]; !exists {
						diags[cd.IP4] = fmt.Sprintf("27=HTTP%d", code)
					}
					markOnline(cd)
					mu.Unlock()
				}
			}()

			// 2) 零 DNS 阿里云 DNS 网页探测
			go func() {
				defer innerWG.Done()
				resp, err := probeGet(cl, "http://223.5.5.5/")
				if err != nil {
					return
				}
				loc, ok := extractCaptiveRedirect(resp, "http://223.5.5.5/")
				code := resp.StatusCode
				resp.Body.Close()
				if ok {
					recordWinner(cd, loc, false)
					return
				}
				if code == 200 || code == 204 || code == 301 || code == 302 {
					mu.Lock()
					if _, exists := diags[cd.IP4]; !exists {
						diags[cd.IP4] = fmt.Sprintf("223=HTTP%d", code)
					}
					markOnline(cd)
					mu.Unlock()
				}
			}()

			// 3) MIUI 204 探测 (并发直连 DNS 已旁路自定义 DNS)
			go func() {
				defer innerWG.Done()
				resp, err := probeGet(cl, "http://connect.rom.miui.com/generate_204")
				if err != nil {
					mu.Lock()
					if _, exists := diags[cd.IP4]; !exists {
						diags[cd.IP4] = fmt.Sprintf("miui=%v", err)
					}
					mu.Unlock()
					return
				}
				loc, ok := extractCaptiveRedirect(resp, "http://connect.rom.miui.com/generate_204")
				code := resp.StatusCode
				resp.Body.Close()
				if ok {
					recordWinner(cd, loc, false)
					return
				}
				mu.Lock()
				diags[cd.IP4] = fmt.Sprintf("miui=HTTP%d", code)
				if code == 204 || code == 200 {
					markOnline(cd)
				}
				mu.Unlock()
			}()

			// 4) 并发常规站点探测 (并发直连 DNS 已钉死物理网卡且拒绝 Fake-IP, 仅用于判定真实外网在线或捕获认证)
			go func() {
				defer innerWG.Done()
				resp, err := probeGet(cl, "http://www.qq.com")
				if err != nil {
					return
				}
				loc, ok := extractCaptiveRedirect(resp, "http://www.qq.com")
				code := resp.StatusCode
				resp.Body.Close()
				if ok {
					recordWinner(cd, loc, true)
					return
				}
				mu.Lock()
				diags[cd.IP4] = fmt.Sprintf("qq=HTTP%d", code)
				markOnline(cd)
				mu.Unlock()
			}()

			innerWG.Wait()
		}(cand)
	}
	wg.Wait()

	if parentCtx.Err() != nil {
		return "", parentCtx.Err()
	}

	if winner != nil {
		ip4 := net.ParseIP(winner.cand.IP4).To4()
		c.mu.Lock()
		c.srcIP = append(net.IP(nil), ip4...)
		c.srcIfIndex = winner.cand.IfIndex
		c.nicName = winner.cand.Name
		c.nicGateway = winner.cand.Gateway
		c.nicDNS = append([]string(nil), winner.cand.DNSServers...)
		if winner.cand.MAC != "" {
			c.mac = winner.cand.MAC
		} else if m := ifaceMACByIP(winner.cand.IP4); m != "" {
			c.mac = strings.ReplaceAll(m, ":", "-")
		}
		macCopy := c.mac
		c.mu.Unlock()
		c.setHTTPClient(boundClientWithNIC(ip4, winner.cand.IfIndex, winner.cand.DNSServers, 10*time.Second, 30*time.Second))
		if winner.second {
			c.logf("INFO", "detect", "校园网出口: %s (ifIndex=%d %s) MAC=%s (并发探测确认未认证)", winner.cand.IP4, winner.cand.IfIndex, winner.cand.Name, macCopy)
		} else {
			c.logf("INFO", "detect", "校园网出口: %s (ifIndex=%d %s) MAC=%s GW=%s", winner.cand.IP4, winner.cand.IfIndex, winner.cand.Name, macCopy, winner.cand.Gateway)
		}
		return winner.loc, nil
	}
	if online {
		// 在线也保留验证通过的物理网卡元数据与直连 HTTP 客户端，便于离线哨兵持续监测
		best := cands[0]
		if onlineCand != nil {
			best = *onlineCand
		}
		ip4 := net.ParseIP(best.IP4).To4()
		c.mu.Lock()
		if ip4 != nil {
			c.srcIP = append(net.IP(nil), ip4...)
		}
		c.nicName = best.Name
		c.srcIfIndex = best.IfIndex
		c.userIP = best.IP4
		c.nicGateway = best.Gateway
		c.nicDNS = append([]string(nil), best.DNSServers...)
		if best.MAC != "" {
			c.mac = best.MAC
		} else if m := ifaceMACByIP(best.IP4); m != "" {
			c.mac = strings.ReplaceAll(m, ":", "-")
		}
		c.mu.Unlock()
		c.setHTTPClient(boundClientWithNIC(ip4, best.IfIndex, best.DNSServers, 5*time.Second, 15*time.Second))
		return "", nil
	}
	for _, cd := range cands {
		c.logf("WARN", "detect", "[探测诊断] %s (%s ifIndex=%d): %s", cd.IP4, cd.Name, cd.IfIndex, diags[cd.IP4])
	}
	return "", errors.New("未检测到需要认证的校园网接口")
}

func (c *Client) extractIndexParams(indexURL string) error {
	uip, aip, pnode, sc, dm, ar := extractSessionParams(indexURL)
	if uip != "" && aip != "" {
		c.setSessionIPs(uip, aip, false)
		c.setPortalNode(pnode, false)
		c.applyDiscoveredSchool(sc, dm, ar)
		return nil
	}
	return errors.New("重定向地址缺少 wlanuserip/wlanacip")
}

// GetEConfig 多跳追踪认证重定向并自动发现 schoolid/domain/area，失败则按规则推导 CGI 地址
func (c *Client) GetEConfig(indexURL string) {
	c.walkRedirectAndConfig(indexURL)
	c.autoDiscoverSchool()
	if c.needAutoSchool() {
		_, aip := c.getSessionIPs()
		c.loadProfileForAC(aip)
	}
	c.mu.Lock()
	if c.ticketURL == "" {
		c.ticketURL = deriveCGI(indexURL, "ticket.cgi")
	}
	if c.authURL == "" {
		c.authURL = deriveCGI(indexURL, "auth.cgi")
	}
	if c.stateURL == "" {
		c.stateURL = deriveCGI(indexURL, "state.cgi")
	}
	c.mu.Unlock()
}

func hostOf(rawURL string) string {
	u := rawURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

func extractTag(s, tag string) string {
	open := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, closeTag)
	if j < 0 {
		return ""
	}
	val := rest[:j]
	if strings.HasPrefix(val, "<![CDATA[") {
		val = strings.TrimPrefix(val, "<![CDATA[")
		if k := strings.LastIndex(val, "]]>"); k >= 0 {
			val = val[:k]
		}
	}
	return strings.TrimSpace(val)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func deriveCGI(indexURL, cgi string) string {
	i := strings.Index(indexURL, "?")
	base := indexURL
	q := ""
	if i >= 0 {
		base, q = indexURL[:i], indexURL[i:]
	}
	slash := strings.LastIndex(base, "/")
	if slash < 0 {
		return base + "/" + cgi + q
	}
	return base[:slash+1] + cgi + q
}

// ---------------- 动态算法 (服务端下发的加密算法模块) ----------------

var (
	blobKeyA = []uint32{0x464B697C, 0x463B6D4D, 0x36496A5A, 0x4774496F}
	blobKeyB = []uint32{0x356D766D, 0x52783633, 0x2D4A4D38, 0x39384335}
)

func xteaDecLE(v0, v1 uint32, key []uint32) (uint32, uint32) {
	const delta uint32 = 0x9E3779B9
	var rounds uint32 = 32
	sum := rounds * delta
	for i := 0; i < 32; i++ {
		v1 -= ((v0 << 4) ^ (v0 >> 5)) + (v0 ^ sum) + key[(sum>>11)&3]
		sum -= delta
		v0 -= ((v1 << 4) ^ (v1 >> 5)) + (v1 ^ sum) + key[sum&3]
	}
	return v0, v1
}

// blobXteaDecrypt 解密 blob 数据段 (小端 ECB, keyA→keyB 双层)
func blobXteaDecrypt(data []byte) []byte {
	out := append([]byte{}, data...)
	for off := 0; off+8 <= len(out); off += 8 {
		v0 := binary.LittleEndian.Uint32(out[off:])
		v1 := binary.LittleEndian.Uint32(out[off+4:])
		v0, v1 = xteaDecLE(v0, v1, blobKeyA)
		v0, v1 = xteaDecLE(v0, v1, blobKeyB)
		binary.LittleEndian.PutUint32(out[off:], v0)
		binary.LittleEndian.PutUint32(out[off+4:], v1)
	}
	return out
}

var aesSboxSig = []byte{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// solvePayload 解析载荷头: "001" + 类型符 + <hex keyhex> + '$' + <UUID algoid> + ']' + <blob>
func solvePayload(payload []byte) (key1, iv []byte, algoid, keyhex string, isAES bool, pe []byte, err error) {
	i := bytes.IndexByte(payload, ']')
	if i < 0 || len(payload) < i+13 {
		return nil, nil, "", "", false, nil, errors.New("载荷缺少 ] 分隔")
	}
	if len(payload) < 72 || !bytes.Equal(payload[:3], []byte("001")) {
		return nil, nil, "", "", false, nil, errors.New("载荷头非 001")
	}
	dollar := bytes.IndexByte(payload, '$')
	if dollar < 4 || dollar+37 > i {
		return nil, nil, "", "", false, nil, errors.New("载荷缺少 $ algoid 分隔")
	}
	algoid = string(payload[dollar+1 : dollar+37])
	if !uuidRe.MatchString(algoid) {
		return nil, nil, "", "", false, nil, fmt.Errorf("algoid 非 UUID: %q", algoid)
	}
	keyhex = string(payload[4:dollar])
	kh, err := hex.DecodeString(keyhex)
	if err != nil || len(kh) < 16 {
		return nil, nil, "", "", false, nil, errors.New("keyhex 非 hex")
	}
	blob := payload[i:]
	if blob[0] != 0x5D {
		return nil, nil, "", "", false, nil, errors.New("blob props 非 LZMA 0x5D")
	}
	dec := blobXteaDecrypt(blob[9:])
	dstSize := uint64(binary.LittleEndian.Uint32(blob[5:9])) & 0xFFFFFFF
	if dstSize < 0x40 || dstSize > 16<<20 {
		return nil, nil, "", "", false, nil, fmt.Errorf("PE 解压长度异常: %d", dstSize)
	}
	hdr := append([]byte{}, blob[0:5]...)
	var sz [8]byte
	binary.LittleEndian.PutUint64(sz[:], dstSize)
	hdr = append(hdr, sz[:]...)
	hdr = append(hdr, dec...)
	r, err := lzma.NewReader(bytes.NewReader(hdr))
	if err != nil {
		return nil, nil, "", "", false, nil, fmt.Errorf("LZMA: %v", err)
	}
	pe = make([]byte, dstSize)
	if _, err := io.ReadFull(r, pe); err != nil {
		return nil, nil, "", "", false, nil, fmt.Errorf("LZMA 解压: %v", err)
	}
	if len(pe) < 0x40 || pe[0] != 'M' || pe[1] != 'Z' {
		return nil, nil, "", "", false, nil, errors.New("算法模块非 MZ/PE")
	}
	e := int(binary.LittleEndian.Uint32(pe[0x3C:]))
	if e < 0 || e+24 > len(pe) || !bytes.Equal(pe[e:e+4], []byte("PE\x00\x00")) {
		return nil, nil, "", "", false, nil, errors.New("算法模块非 PE")
	}
	nsec := int(binary.LittleEndian.Uint16(pe[e+6:]))
	optSize := int(binary.LittleEndian.Uint16(pe[e+20:]))
	secOff := e + 24 + optSize
	if secOff < 0 || secOff > len(pe) {
		return nil, nil, "", "", false, nil, errors.New("PE 节表偏移越界")
	}
	type sec struct{ va, vsz, roff, rsz uint32 }
	secs := make([]sec, 0, nsec)
	for k := 0; k < nsec && secOff+40*(k+1) <= len(pe); k++ {
		s := pe[secOff+40*k:]
		secs = append(secs, sec{
			va:   binary.LittleEndian.Uint32(s[12:]),
			vsz:  binary.LittleEndian.Uint32(s[8:]),
			roff: binary.LittleEndian.Uint32(s[20:]),
			rsz:  binary.LittleEndian.Uint32(s[24:]),
		})
	}
	rva2raw := func(rva uint32) int {
		for _, s := range secs {
			if rva >= s.va && rva < s.va+maxU32(s.vsz, s.rsz) {
				return int(s.roff) + int(rva-s.va)
			}
		}
		return -1
	}
	getByte := func(rva uint32) (byte, error) {
		if o := rva2raw(rva); o >= 0 && o < len(pe) {
			return pe[o], nil
		}
		return 0, fmt.Errorf("RVA 0x%x 不在任何节内", rva)
	}
	l1, l1err := getByte(0xB183)     // KEY1 长度
	off1, off1err := getByte(0xB186) // KEY1 在池内的偏移
	if l1err != nil || off1err != nil || l1 == 0 {
		return nil, nil, algoid, keyhex, false, pe, nil // 非 AES 模板 → DLL 执行引擎
	}
	ko := rva2raw(0xB088 + uint32(off1))
	if ko < 0 || ko+int(l1) > len(pe) {
		return nil, nil, algoid, keyhex, false, pe, nil
	}
	key1 = append([]byte{}, pe[ko:ko+int(l1)]...)
	iv = append([]byte{}, kh[:16]...)
	marker, markerErr := getByte(0xB187)
	isAES = markerErr == nil && marker == 0xcd && bytes.Contains(pe, aesSboxSig) && len(key1) == 32
	if !isAES {
		return nil, nil, algoid, keyhex, false, pe, nil
	}
	return key1, iv, algoid, keyhex, true, pe, nil
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// dynAesCipher 动态算法: 双层 AES-128-CBC, KEY1=32B 拆两把, IV=keyhex 前 16 字节
type dynAesCipher struct {
	key1, iv       []byte
	once           sync.Once
	blockA, blockB cipher.Block
	initErr        error
}

func (c *dynAesCipher) initBlocks() error {
	c.once.Do(func() {
		if len(c.key1) < 32 || len(c.iv) < 16 {
			c.initErr = errors.New("dynAesCipher key1/iv 长度不足")
			return
		}
		c.blockA, c.initErr = aes.NewCipher(c.key1[:16])
		if c.initErr != nil {
			return
		}
		c.blockB, c.initErr = aes.NewCipher(c.key1[16:32])
	})
	return c.initErr
}

func (c *dynAesCipher) Encrypt(p []byte) (string, error) {
	if err := c.initBlocks(); err != nil {
		return "", err
	}
	iv16 := c.iv[:16]
	pad := (16 - (len(p)+1)%16) % 16
	data := append(append([]byte{}, p...), make([]byte, 1+pad)...)
	l1 := make([]byte, 16+len(data))
	copy(l1, iv16)
	cipher.NewCBCEncrypter(c.blockA, iv16).CryptBlocks(l1[16:], data)
	l2 := make([]byte, 16+len(l1))
	copy(l2, iv16)
	cipher.NewCBCEncrypter(c.blockB, iv16).CryptBlocks(l2[16:], l1)
	return strings.ToUpper(hex.EncodeToString(l2)), nil
}

func (c *dynAesCipher) Decrypt(h string) ([]byte, error) {
	if err := c.initBlocks(); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.ToLower(h))
	if err != nil || len(raw) < 32 || len(raw)%16 != 0 {
		return nil, errors.New("响应 hex 无效")
	}
	t1 := make([]byte, len(raw)-16)
	cipher.NewCBCDecrypter(c.blockB, raw[:16]).CryptBlocks(t1, raw[16:])
	if len(t1) < 32 || len(t1)%16 != 0 {
		return nil, errors.New("响应内层长度无效")
	}
	t2 := make([]byte, len(t1)-16)
	cipher.NewCBCDecrypter(c.blockA, t1[:16]).CryptBlocks(t2, t1[16:])
	return trimZero(t2), nil
}

// 已知学校的 Portal 认证节点表（默认留空，完全依赖零配置自动发现与 portal_cache.txt）
var knownPortals = map[string]string{}

const portalCacheFile = "portal_cache.txt"
const sessionFile = "session.txt"
const profileFile = "profile.txt"

func (c *Client) loadProfile() {
	c.loadProfileForAC("")
}

func (c *Client) loadProfileForAC(acIP string) {
	b, err := os.ReadFile(profileFile)
	if err != nil {
		return
	}
	kv := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if pp := strings.SplitN(strings.TrimSpace(ln), "=", 2); len(pp) == 2 {
			kv[pp[0]] = pp[1]
		}
	}
	if acIP != "" && kv["acIP"] != "" && kv["acIP"] != acIP {
		return
	}
	c.mu.Lock()
	if c.school == "" && c.cmdSchool == "" {
		c.school = kv["school"]
	}
	if c.domain == "" && c.cmdDomain == "" {
		c.domain = kv["domain"]
	}
	if c.area == "" && c.cmdArea == "" {
		c.area = kv["area"]
	}
	c.mu.Unlock()
}

func (c *Client) saveProfile() {
	c.mu.Lock()
	aip := c.acIP
	sc, dm, ar := c.school, c.domain, c.area
	c.mu.Unlock()
	if sc == "" && dm == "" && ar == "" {
		return
	}
	lines := []string{
		"acIP=" + aip,
		"school=" + sc,
		"domain=" + dm,
		"area=" + ar,
	}
	_ = os.WriteFile(profileFile, []byte(strings.Join(lines, "\n")), 0644)
}

func (c *Client) markPortalDead(rawURL string) {
	root := strings.ToLower(portalRoot(strings.TrimSpace(rawURL)))
	if !strings.HasPrefix(root, "http") {
		return
	}
	c.mu.Lock()
	if c.deadPortals == nil {
		c.deadPortals = map[string]bool{}
	}
	c.deadPortals[root] = true
	c.mu.Unlock()
}

func (c *Client) isPortalDead(rawURL string) bool {
	root := strings.ToLower(portalRoot(strings.TrimSpace(rawURL)))
	if root == "" {
		return false
	}
	c.mu.Lock()
	dead := c.deadPortals != nil && c.deadPortals[root]
	c.mu.Unlock()
	return dead
}

// savePortalCache 保存当前可用的认证节点与同 AC 集群兄弟节点到 portal_cache.txt (第 1 行为主 URL，兼容单行旧读取)
func (c *Client) savePortalCache(primaryURL string) {
	c.mu.Lock()
	acIP := strings.TrimSpace(c.acIP)
	keepRoot := portalRoot(c.keepURL)
	clusters := append([]string(nil), c.clusterServers...)
	c.mu.Unlock()

	var nodes []string
	seen := map[string]bool{}
	addNode := func(u string) {
		r := portalRoot(strings.TrimSpace(u))
		low := strings.ToLower(r)
		if !strings.HasPrefix(low, "http") || seen[low] || c.isPortalDead(r) {
			return
		}
		seen[low] = true
		nodes = append(nodes, r)
	}
	// 若 keepURL 为健康 :7001 集群节点而 primaryURL 仅是 :10001 调度节点，优先缓存集群 :7001 节点
	if keepRoot != "" && strings.Contains(strings.ToLower(keepRoot), ":7001") {
		addNode(keepRoot)
	}
	addNode(primaryURL)
	for _, cs := range clusters {
		addNode(cs)
	}
	if len(nodes) == 0 {
		return
	}
	var lines []string
	lines = append(lines, nodes[0])
	if acIP != "" {
		lines = append(lines, "acIP="+acIP)
	}
	lines = append(lines, nodes[1:]...)
	_ = os.WriteFile(portalCacheFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// loadPortalCache 读取同一 AC 下的已缓存门户集群节点；跨校 AC 不匹配时自动忽略以免误连外校节点
func loadPortalCache(acIP string) []string {
	b, err := os.ReadFile(portalCacheFile)
	if err != nil {
		return nil
	}
	var urls []string
	cachedAC := ""
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "acIP=") {
			cachedAC = strings.TrimSpace(strings.TrimPrefix(ln, "acIP="))
			continue
		}
		if strings.HasPrefix(strings.ToLower(ln), "http") {
			low := strings.ToLower(ln)
			if !seen[low] {
				seen[low] = true
				urls = append(urls, ln)
			}
		}
	}
	if acIP != "" && cachedAC != "" && cachedAC != acIP {
		return nil
	}
	return urls
}

func (c *Client) candidateTicketURLs() []string {
	c.mu.Lock()
	uip, aip := c.userIP, c.acIP
	pPage, tURL := c.portalPage, c.ticketURL
	clusters := append([]string(nil), c.clusterServers...)
	sc := c.school
	c.mu.Unlock()

	q := fmt.Sprintf("?wlanuserip=%s&wlanacip=%s", uip, aip)
	var raw []string
	seen := map[string]bool{}
	add := func(base, path string) {
		if base == "" {
			return
		}
		u := strings.TrimRight(base, "/") + path
		if !strings.Contains(u, "?") {
			u += q
		}
		if seen[u] {
			return
		}
		seen[u] = true
		raw = append(raw, u)
	}
	if pPage != "" && strings.Contains(strings.ToLower(pPage), ":7001") {
		add(portalRoot(pPage), "/ticket.cgi")
	}
	add(tURL, "")
	for _, cs := range clusters {
		add(cs, "/ticket.cgi")
	}
	for _, cb := range loadPortalCache(aip) {
		add(cb, "/ticket.cgi")
	}
	if p, ok := knownPortals[sc]; ok {
		add(p, "/ticket.cgi")
	}
	if aip != "" {
		add(fmt.Sprintf("http://%s:7001", aip), "/ticket.cgi")
	}

	var tier1, tier2, tier3 []string
	for _, u := range raw {
		if c.isPortalDead(u) {
			tier3 = append(tier3, u)
			continue
		}
		if strings.Contains(strings.ToLower(portalRoot(u)), ":10001") {
			tier2 = append(tier2, u)
			continue
		}
		tier1 = append(tier1, u)
	}
	out := make([]string, 0, len(raw))
	out = append(out, tier1...)
	out = append(out, tier2...)
	out = append(out, tier3...)
	return out
}

func portalRoot(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return strings.TrimRight(u, "/")
	}
	rest := u[i+3:]
	if j := strings.IndexAny(rest, "/?"); j >= 0 {
		return u[:i+3+j]
	}
	return u
}

func (c *Client) rebaseToPortal(portalURL string) {
	base := portalRoot(portalURL)
	q := ""
	if i := strings.Index(portalURL, "?"); i >= 0 {
		q = portalURL[i:]
	}
	c.mu.Lock()
	c.ticketURL = base + "/ticket.cgi" + q
	c.authURL = base + "/auth.cgi" + q
	c.stateURL = base + "/state.cgi" + q
	c.mu.Unlock()
}

const (
	probeOK = iota
	probeRetry
	probeNext
)

const (
	maxHTTPHeadSize = 64 << 10
	maxHTTPBodySize = 32 << 20
)

var gatewayRetryDelays = []time.Duration{
	80 * time.Millisecond,
	150 * time.Millisecond,
	250 * time.Millisecond,
	350 * time.Millisecond,
	500 * time.Millisecond,
}

func isTransientGatewayStatus(status int) bool {
	return status == 502 || status == 503 || status == 504
}

func isTransientGateway(status int, hdrs [][2]string) bool {
	return isTransientGatewayStatus(status) && hdrGet(hdrs, "Error-Code") == ""
}

// rawHTTP 原始 HTTP/1.1 客户端 (绑定校园网源 IP, 头部顺序与大小写完全可控)
func (c *Client) rawHTTP(rawURL string, headers [][2]string, body []byte) (int, [][2]string, []byte, error) {
	return c.rawHTTPWithTimeout(rawURL, headers, body, 12*time.Second, 30*time.Second)
}

func (c *Client) rawHTTPWithRetry(rawURL string, headers [][2]string, body []byte, dialTimeout, rwTimeout time.Duration, maxRetries int) (int, [][2]string, []byte, error) {
	for attempt := 0; ; attempt++ {
		status, hdrs, rbody, err := c.rawHTTPWithTimeout(rawURL, headers, body, dialTimeout, rwTimeout)
		if err != nil || !isTransientGateway(status, hdrs) || attempt >= maxRetries {
			return status, hdrs, rbody, err
		}
		delay := gatewayRetryDelays[minInt(attempt, len(gatewayRetryDelays)-1)]
		if isDebugMode() {
			fmt.Printf("[HTTP] %s 返回 HTTP %d，%dms 后重试 (%d/%d)\n", rawURL, status, delay.Milliseconds(), attempt+1, maxRetries)
		}
		if !sleepCtx(c.activeCtx(), delay) {
			return 0, nil, nil, c.activeCtx().Err()
		}
	}
}

func buildRawPOSTRequest(path, hostport string, headers [][2]string, body []byte) []byte {
	// 与官方客户端线上字节完全一致的头顺序:
	// 请求行 -> Connection -> User-Agent -> 业务头 -> Content-Length -> Host
	req := &bytes.Buffer{}
	fmt.Fprintf(req, "POST %s HTTP/1.1\r\n", path)
	fmt.Fprintf(req, "Connection: close\r\n")
	fmt.Fprintf(req, "User-Agent: %s\r\n", UserAgent)
	for _, kv := range headers {
		fmt.Fprintf(req, "%s: %s\r\n", kv[0], kv[1])
	}
	fmt.Fprintf(req, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(req, "Host: %s\r\n", hostport)
	req.WriteString("\r\n")
	req.Write(body)
	return req.Bytes()
}

func parseHTTPHeaderBlock(head []byte) (status int, hdrs [][2]string, chunked bool) {
	lines := strings.Split(string(head), "\r\n")
	if len(lines) > 0 {
		if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
			status, _ = strconv.Atoi(parts[1])
		}
	}
	for _, ln := range lines[1:] {
		if j := strings.Index(ln, ":"); j > 0 {
			name := ln[:j]
			val := strings.TrimSpace(ln[j+1:])
			hdrs = append(hdrs, [2]string{name, val})
			if strings.EqualFold(name, "Transfer-Encoding") && strings.Contains(strings.ToLower(val), "chunked") {
				chunked = true
			}
		}
	}
	return status, hdrs, chunked
}

func parseRawPostURL(rawURL string) (u *url.URL, host, port, hostport, path string, err error) {
	u, err = url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, "", "", "", "", fmt.Errorf("无效 URL: %q", rawURL)
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	path = u.RequestURI()
	if path == "" {
		path = "/"
	}
	return u, host, port, u.Host, path, nil
}

func (c *Client) rawHTTPWithTimeout(rawURL string, headers [][2]string, body []byte, dialTimeout, rwTimeout time.Duration) (int, [][2]string, []byte, error) {
	u, host, port, hostport, path, err := parseRawPostURL(rawURL)
	if err != nil {
		return 0, nil, nil, err
	}

	readResp := func(conn net.Conn) (int, [][2]string, []byte, error) {
		conn.SetDeadline(time.Now().Add(rwTimeout))
		head, rbody, err := readHTTPMessage(conn)
		if err != nil {
			return 0, nil, nil, err
		}
		status, hdrs, chunked := parseHTTPHeaderBlock(head)
		if chunked {
			return status, hdrs, dechunk(rbody), nil
		}
		return status, hdrs, rbody, nil
	}

	tStart := time.Now()
	ctx := c.activeCtx()
	srcIP, ifIdx, dns := c.getNICBind()
	d := newPinnedDialer(srcIP, ifIdx, dns, dialTimeout)
	cands, err := resolvePinnedIP4Candidates(ctx, srcIP, ifIdx, dns, net.JoinHostPort(host, port))
	if err != nil {
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method: "POST", URL: rawURL, RTTMs: time.Since(tStart).Milliseconds(),
				ReqBytes: len(body), Error: err.Error(),
			}, c.pass, c.user)
		}
		return 0, nil, nil, err
	}
	var conn net.Conn
	for _, cand := range cands {
		conn, err = d.DialContext(ctx, "tcp4", cand)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method: "POST", URL: rawURL, RTTMs: time.Since(tStart).Milliseconds(),
				ReqBytes: len(body), Error: err.Error(),
			}, c.pass, c.user)
		}
		return 0, nil, nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	if strings.EqualFold(u.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
		tlsTO := rwTimeout
		if tlsTO > 15*time.Second {
			tlsTO = 15 * time.Second
		}
		tlsConn.SetDeadline(time.Now().Add(tlsTO))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return 0, nil, nil, err
		}
		conn = tlsConn
	}
	reqBytes := buildRawPOSTRequest(path, hostport, headers, body)
	conn.SetDeadline(time.Now().Add(rwTimeout))
	if _, err := conn.Write(reqBytes); err != nil {
		conn.Close()
		return 0, nil, nil, err
	}
	status, hdrs, rbody, err := readResp(conn)
	conn.Close()
	rtt := time.Since(tStart).Milliseconds()
	if err != nil {
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method: "POST", URL: rawURL, RTTMs: rtt,
				ReqBytes: len(body), Error: err.Error(),
			}, c.pass, c.user)
		}
		return 0, nil, nil, err
	}
	ec := hdrGet(hdrs, "Error-Code")
	if c.diag != nil {
		preview := ""
		if status != 200 || (ec != "0" && ec != "200") || isDebugMode() {
			preview = string(rbody[:minInt(len(rbody), 160)])
		}
		c.diag.AddWire(WireEntry{
			Method:      "POST",
			URL:         rawURL,
			Status:      status,
			RTTMs:       rtt,
			ErrorCode:   ec,
			ServerTag:   hdrGet(hdrs, "Server-Tag"),
			ReqBytes:    len(body),
			RespBytes:   len(rbody),
			BodyPreview: preview,
		}, c.pass, c.user)
	}
	if isDebugMode() {
		dumpWireWithResp(reqBytes, headOf(hdrs, status))
	}
	return status, hdrs, rbody, nil
}

func headOf(hdrs [][2]string, status int) []byte {
	head := fmt.Sprintf("HTTP/1.1 %d\n", status)
	for _, kv := range hdrs {
		head += kv[0] + ": " + kv[1] + "\n"
	}
	return []byte(head)
}

func parseChunkSize(line []byte) (int64, error) {
	s := string(line)
	if j := strings.IndexByte(s, ';'); j >= 0 {
		s = s[:j]
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 16, 64)
	if err != nil || n < 0 || n > maxHTTPBodySize {
		return 0, errors.New("invalid chunk size")
	}
	return n, nil
}

// dechunk 解析 chunked 流为纯 body (支持 chunk-ext 与空白，防止 32 位负值溢出)
func dechunk(rest []byte) []byte {
	var out bytes.Buffer
	for {
		i := bytes.Index(rest, []byte("\r\n"))
		if i < 0 {
			break
		}
		n, err := parseChunkSize(rest[:i])
		if err != nil || n == 0 {
			break
		}
		rest = rest[i+2:]
		if int64(len(rest)) < n+2 {
			break
		}
		out.Write(rest[:n])
		rest = rest[n+2:]
	}
	return out.Bytes()
}

// chunkedComplete 判断 chunked 流是否已完整接收 (含终止 chunk 0 及其尾部 CRLF)
func chunkedComplete(data []byte) bool {
	return scanChunked(data, false)
}

// chunkedHasTerminator 判断在 EOF 场景下是否至少已收到 0\r\n 终止块
func chunkedHasTerminator(data []byte) bool {
	return scanChunked(data, true)
}

func scanChunked(data []byte, allowEOFAfterZero bool) bool {
	rest := data
	for {
		i := bytes.Index(rest, []byte("\r\n"))
		if i < 0 {
			return false
		}
		n, err := parseChunkSize(rest[:i])
		if err != nil {
			return true // 非法 chunk 序列 → 交给上层容错
		}
		afterSize := rest[i+2:]
		if n == 0 {
			if allowEOFAfterZero {
				return true
			}
			// 终止 chunk 后必须跟随 "\r\n" (无 trailer) 或 trailers+"\r\n\r\n"
			if bytes.HasPrefix(afterSize, []byte("\r\n")) || bytes.Contains(afterSize, []byte("\r\n\r\n")) {
				return true
			}
			return false
		}
		if int64(len(afterSize)) < n+2 {
			return false
		}
		rest = afterSize[n+2:]
	}
}

var httpReadBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 8192)
		return &b
	},
}

// readHTTPHeadersOnly 仅读取 HTTP 响应头 (\r\n\r\n)，供 term.cgi 等可能不带体或不回包接口快速判定
func readHTTPHeadersOnly(conn net.Conn) ([]byte, error) {
	var buf bytes.Buffer
	tmpPtr := httpReadBufPool.Get().(*[]byte)
	defer httpReadBufPool.Put(tmpPtr)
	tmp := *tmpPtr
	for {
		if idx := bytes.Index(buf.Bytes(), []byte("\r\n\r\n")); idx >= 0 {
			return append([]byte(nil), buf.Bytes()[:idx]...), nil
		}
		if buf.Len() > maxHTTPHeadSize {
			return nil, errors.New("HTTP 响应头过大")
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if idx := bytes.Index(buf.Bytes(), []byte("\r\n\r\n")); idx >= 0 {
				return append([]byte(nil), buf.Bytes()[:idx]...), nil
			}
			return nil, err
		}
	}
}

// rawHTTPPostTerm 发送注销 POST，使用独立后台超时（不受认证 ctx 取消影响），且发包后对服务端静默/断流快速容错
func (c *Client) rawHTTPPostTerm(rawURL string, headers [][2]string, body []byte, dialTimeout, readWait time.Duration) (sent bool, status int, hdrs [][2]string, err error) {
	u, host, port, hostport, path, err := parseRawPostURL(rawURL)
	if err != nil {
		return false, 0, nil, err
	}
	tStart := time.Now()
	srcIP, ifIdx, dns := c.getNICBind()
	d := newPinnedDialer(srcIP, ifIdx, dns, dialTimeout)
	cands, err := resolvePinnedIP4Candidates(context.Background(), srcIP, ifIdx, dns, net.JoinHostPort(host, port))
	if err != nil {
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method: "POST", URL: rawURL, RTTMs: time.Since(tStart).Milliseconds(),
				ReqBytes: len(body), Error: err.Error(),
			}, c.pass, c.user)
		}
		return false, 0, nil, err
	}
	var conn net.Conn
	for _, cand := range cands {
		conn, err = d.Dial("tcp4", cand)
		if err == nil {
			break
		}
	}
	if err != nil {
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method: "POST", URL: rawURL, RTTMs: time.Since(tStart).Milliseconds(),
				ReqBytes: len(body), Error: err.Error(),
			}, c.pass, c.user)
		}
		return false, 0, nil, err
	}
	if strings.EqualFold(u.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
		tlsConn.SetDeadline(time.Now().Add(dialTimeout))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			if c.diag != nil {
				c.diag.AddWire(WireEntry{
					Method: "POST", URL: rawURL, RTTMs: time.Since(tStart).Milliseconds(),
					ReqBytes: len(body), Error: err.Error(),
				}, c.pass, c.user)
			}
			return false, 0, nil, err
		}
		conn = tlsConn
	}
	reqBytes := buildRawPOSTRequest(path, hostport, headers, body)
	conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err := conn.Write(reqBytes); err != nil {
		conn.Close()
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method: "POST", URL: rawURL, RTTMs: time.Since(tStart).Milliseconds(),
				ReqBytes: len(body), Error: err.Error(),
			}, c.pass, c.user)
		}
		return false, 0, nil, err
	}
	sent = true
	conn.SetDeadline(time.Now().Add(readWait))
	head, rerr := readHTTPHeadersOnly(conn)
	conn.Close()
	rtt := time.Since(tStart).Milliseconds()
	if rerr != nil {
		if c.diag != nil {
			c.diag.AddWire(WireEntry{
				Method:      "POST",
				URL:         rawURL,
				Status:      204,
				RTTMs:       rtt,
				ReqBytes:    len(body),
				BodyPreview: "注销已发出，服务端未回包/链路已断开(正常)",
			}, c.pass, c.user)
		}
		return true, 0, nil, rerr
	}
	status, hdrs, _ = parseHTTPHeaderBlock(head)
	ec := hdrGet(hdrs, "Error-Code")
	if c.diag != nil {
		c.diag.AddWire(WireEntry{
			Method:    "POST",
			URL:       rawURL,
			Status:    status,
			RTTMs:     rtt,
			ErrorCode: ec,
			ServerTag: hdrGet(hdrs, "Server-Tag"),
			ReqBytes:  len(body),
		}, c.pass, c.user)
	}
	if isDebugMode() {
		dumpWireWithResp(reqBytes, headOf(hdrs, status))
	}
	return true, status, hdrs, nil
}

// readHTTPMessage 从连接读取一个 HTTP 报文 (头 + 完整体)
func readHTTPMessage(conn net.Conn) ([]byte, []byte, error) {
	var buf bytes.Buffer
	tmpPtr := httpReadBufPool.Get().(*[]byte)
	defer httpReadBufPool.Put(tmpPtr)
	tmp := *tmpPtr
	for {
		if bytes.Index(buf.Bytes(), []byte("\r\n\r\n")) >= 0 {
			break
		}
		if buf.Len() > maxHTTPHeadSize {
			return nil, nil, errors.New("HTTP 响应头过大")
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if bytes.Index(buf.Bytes(), []byte("\r\n\r\n")) >= 0 {
				break
			}
			return nil, nil, err
		}
	}
	headLen := bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
	bodyStart := headLen + 4
	headCopy := string(buf.Bytes()[:headLen])
	lines := strings.Split(headCopy, "\r\n")
	status := 0
	if len(lines) > 0 {
		if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
			status, _ = strconv.Atoi(parts[1])
		}
	}
	clen := -1
	chunked := false
	for _, ln := range lines[1:] {
		if j := strings.Index(ln, ":"); j > 0 {
			name := ln[:j]
			val := strings.TrimSpace(ln[j+1:])
			switch strings.ToLower(name) {
			case "content-length":
				if v, e := strconv.Atoi(val); e == nil && v >= 0 {
					clen = v
				}
			case "transfer-encoding":
				if strings.Contains(strings.ToLower(val), "chunked") {
					chunked = true
				}
			}
		}
	}

	if chunked {
		for !chunkedComplete(buf.Bytes()[bodyStart:]) {
			if buf.Len()-bodyStart > maxHTTPBodySize {
				return nil, nil, errors.New("HTTP chunked 响应体过大")
			}
			n, err := conn.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
			}
			if err != nil {
				if err == io.EOF && chunkedHasTerminator(buf.Bytes()[bodyStart:]) {
					break
				}
				if err == io.EOF {
					return nil, nil, io.ErrUnexpectedEOF
				}
				return nil, nil, err
			}
		}
		d := buf.Bytes()
		return d[:headLen], d[bodyStart:], nil
	}

	if clen >= 0 {
		if clen > maxHTTPBodySize {
			return nil, nil, errors.New("HTTP Content-Length 过大")
		}
		for buf.Len()-bodyStart < clen {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
			}
			if err != nil {
				if buf.Len()-bodyStart >= clen {
					break
				}
				if err == io.EOF {
					return nil, nil, io.ErrUnexpectedEOF
				}
				return nil, nil, err
			}
		}
		d := buf.Bytes()
		rest := d[bodyStart:]
		if len(rest) > clen {
			rest = rest[:clen]
		}
		return d[:headLen], rest, nil
	}

	// 无 Content-Length 且非 chunked: 1xx/204/304 无体；否则按 Connection: close 读至 EOF
	if status == 204 || status == 304 || (status >= 100 && status < 200) {
		d := buf.Bytes()
		return d[:headLen], nil, nil
	}
	for {
		if buf.Len()-bodyStart > maxHTTPBodySize {
			return nil, nil, errors.New("HTTP 响应体过大")
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, err
		}
	}
	d := buf.Bytes()
	return d[:headLen], d[bodyStart:], nil
}

func hdrGet(hdrs [][2]string, name string) string {
	for _, kv := range hdrs {
		if strings.EqualFold(kv[0], name) {
			return kv[1]
		}
	}
	return ""
}

// dumpWireWithResp 把请求行/头与响应行/头转储到 zsm_wire.log (仅 -debug 模式)
func dumpWireWithResp(req []byte, respHead []byte) {
	i := bytes.Index(req, []byte("\r\n\r\n"))
	var b bytes.Buffer
	b.WriteString("==== " + time.Now().Format("15:04:05.000") + " ====\n")
	if i >= 0 {
		b.Write(req[:i])
		b.WriteString(fmt.Sprintf("\n[BODY %d] %x\n", len(req[i+4:]), req[i+4:]))
	} else {
		b.Write(req)
	}
	f, err := os.OpenFile("zsm_wire.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(b.Bytes())
	_, _ = f.Write(append([]byte("--RESP--\n"), respHead...))
	_, _ = f.Write([]byte("\n"))
}

// cdcHeaders 认证请求的 CDC 头
func (c *Client) cdcHeaders() [][2]string {
	sc, dm, ar := c.getSchoolInfo()
	var h [][2]string
	if sc != "" {
		h = append(h, [2]string{"CDC-SchoolId", sc})
	}
	if dm != "" {
		h = append(h, [2]string{"CDC-Domain", dm})
	}
	if ar != "" {
		h = append(h, [2]string{"CDC-Area", ar})
	}
	return h
}

const officialProbeBody = "tarce log algo auto compstr null value"

func (c *Client) closeCipherLocked() {
	if cl, ok := c.cipher.(interface{ Close() }); ok {
		cl.Close()
	}
	c.cipher = nil
}

func (c *Client) setCipher(algoID string, ci Cipher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cipher != ci {
		c.closeCipherLocked()
	}
	c.algoID = algoID
	c.cipher = ci
}

func (c *Client) setCipherAndFamily(algoID, family string, ci Cipher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cipher != ci {
		c.closeCipherLocked()
	}
	c.algoID = algoID
	c.algoFamily = family
	c.cipher = ci
}

func (c *Client) probeOneTicketURL(url string, dialTimeout, rwTimeout time.Duration) ([]byte, int, error) {
	body := []byte(officialProbeBody)
	c.mu.Lock()
	c.clientID = randUUID()
	cid := c.clientID
	c.mu.Unlock()
	headers := append([][2]string{
		{"Algo-ID", zeroAlgoID},
		{"Client-ID", cid},
		{"CDC-Checksum", fmt.Sprintf("%x", md5.Sum(body))},
	}, c.cdcHeaders()...)
	status, hdrs, data, err := c.rawHTTPWithRetry(url, headers, body, dialTimeout, rwTimeout, 5)
	if err != nil {
		return nil, probeNext, err
	}
	if status != 200 || len(data) < 40 {
		if status == 200 {
			return data, probeRetry, fmt.Errorf("HTTP 200 未下发载荷 (EC=%s len=%d)", hdrGet(hdrs, "Error-Code"), len(data))
		}
		return data, probeNext, fmt.Errorf("HTTP %d (len=%d)", status, len(data))
	}
	if isDebugMode() {
		_ = os.WriteFile("zsm_payload_last.bin", data, 0644)
	}
	return data, probeOK, nil
}

func (c *Client) negotiateAlgo() error {
	ctx := c.activeCtx()
	var lastErr error
	urls := c.candidateTicketURLs()
	if len(urls) > 1 {
		// 第一轮快速故障转移: 每个候选最多试 2 次 (2s 建连超时), 失效节点立即标记死节点并换下一候选
		for _, url := range urls {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if c.tryCandidate(url, 2, 150*time.Millisecond, 2*time.Second, 8*time.Second, &lastErr) {
				return nil
			}
		}
	}
	// 第二轮完整重试 (优先按死节点降权后的最新顺序尝试, 遵守服务端限速间隔)
	for _, url := range c.candidateTicketURLs() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.tryCandidate(url, 10, 400*time.Millisecond, 4*time.Second, 25*time.Second, &lastErr) {
			return nil
		}
	}
	return fmt.Errorf("动态算法探测失败: %v", lastErr)
}

func (c *Client) tryCandidate(url string, maxAttempts int, baseWait, dialTimeout, rwTimeout time.Duration, lastErr *error) bool {
	ctx := c.activeCtx()
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			*lastErr = ctx.Err()
			return false
		}
		if attempt > 0 {
			wait := baseWait
			if attempt >= 3 {
				wait = 2500 * time.Millisecond
			} else if attempt == 2 && baseWait < 1500*time.Millisecond {
				wait = 1500 * time.Millisecond
			}
			if !sleepCtx(ctx, wait) {
				*lastErr = ctx.Err()
				return false
			}
		}
		data, st, err := c.probeOneTicketURL(url, dialTimeout, rwTimeout)
		switch st {
		case probeNext:
			if err != nil {
				*lastErr = fmt.Errorf("%s: %v", url, err)
				c.markPortalDead(url)
				c.logf("INFO", "negotiate", "[探测] 跳过接口: %v", *lastErr)
			}
			return false
		case probeRetry:
			*lastErr = fmt.Errorf("%s: %v", url, err)
			if attempt == 0 {
				c.logf("INFO", "negotiate", "[探测] 未下发载荷, 重试中: %v", *lastErr)
			}
			// 若服务端明确以空 body + EC=1/2/12 拒绝动态探针，快速让位于静态算法探测
			msg := err.Error()
			if len(data) == 0 && (strings.Contains(msg, "EC=1 ") || strings.Contains(msg, "EC=2 ") || strings.Contains(msg, "EC=12 ")) && attempt >= 1 {
				return false
			}
			continue
		}
		key1, iv, algoid, keyhexStr, isAES, pe, err := solvePayload(data)
		if err != nil {
			if ci, said, serr := decodeStaticTicket(data); serr == nil {
				if isDebugMode() {
					_ = os.WriteFile("zsm_payload_"+said[:8]+".bin", data, 0644)
				}
				c.logf("INFO", "negotiate", "[载荷] 静态算法 algoid=%s", said)
				c.savePortalCache(url)
				c.rebaseToPortal(url)
				c.setCipherAndFamily(said, "静态算法", ci)
				return true
			}
			*lastErr = fmt.Errorf("%s: %v", url, err)
			if attempt == 0 {
				c.logf("WARN", "negotiate", "[探测] 载荷变体: %v", err)
			}
			continue
		}
		if !isAES {
			if isDebugMode() {
				_ = os.WriteFile("zsm_variant_"+algoid[:8]+".bin", data, 0644)
			}
			c.logf("INFO", "negotiate", "[载荷] 类型=0x%02x algoid=%s 非 AES 变体 (gen 家族)", data[3], algoid)
			if os.Getenv("DLL_ENGINE") != "0" {
				if _, e1 := findFuncRVA(pe, dllCodePat); e1 == nil {
					if _, e2 := findFuncRVA(pe, dllDecPat); e2 == nil {
						// 并行前置 Preflight，与 DLL worker 启动/自检重叠执行
						c.rebaseToPortal(url)
						var pfWG sync.WaitGroup
						pfWG.Add(1)
						go func() {
							defer pfWG.Done()
							c.Preflight()
						}()
						dc, engineLabel, eInit := newDynamicDLLCipher(pe, keyhexStr)
						var e3 error
						if eInit != nil {
							e3 = eInit
						} else {
							_, e3 = dc.Encrypt([]byte("<t/>"))
						}
						pfWG.Wait()
						if e3 == nil {
							c.logf("INFO", "negotiate", "[载荷] → %s (自检通过)", engineLabel)
							c.savePortalCache(url)
							c.setCipherAndFamily(algoid, engineLabel, dc)
							return true
						}
						if cl, ok := dc.(interface{ Close() }); ok {
							cl.Close()
						}
						c.logf("WARN", "negotiate", "[载荷] DLL 引擎自检未通过 (%v), 等服务端轮换", e3)
					}
				}
			}
			*lastErr = fmt.Errorf("%s: 非 AES 变体 (服务端轮换), 重试中", url)
			continue
		}
		c.logf("INFO", "negotiate", "[载荷] 类型=0x%02x algoid=%s key1[:8]=%s", data[3], algoid, hex.EncodeToString(key1[:8]))
		if isDebugMode() {
			_ = os.WriteFile("zsm_payload_"+algoid[:8]+".bin", data, 0644)
		}
		c.savePortalCache(url)
		c.rebaseToPortal(url)
		c.setCipherAndFamily(algoid, "动态 AES-128-CBC", &dynAesCipher{key1: key1, iv: iv})
		c.logf("INFO", "negotiate", "认证节点: %s", portalRoot(url))
		return true
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// negotiateAlgoStatic 静态算法后备
func (c *Client) negotiateAlgoStatic() error {
	body := []byte(zeroAlgoID + "\r\n")
	var lastErr error
	for _, url := range c.candidateTicketURLs() {
		c.mu.Lock()
		cid := c.clientID
		c.mu.Unlock()
		headers := append([][2]string{
			{"Algo-ID", zeroAlgoID},
			{"Client-ID", cid},
			{"CDC-Checksum", fmt.Sprintf("%x", md5.Sum(body))},
		}, c.cdcHeaders()...)
		status, hdrs, data, err := c.rawHTTPWithRetry(url, headers, body, 3*time.Second, 15*time.Second, 3)
		if err != nil {
			lastErr = fmt.Errorf("%s: %v", url, err)
			continue
		}
		if status != 200 || hdrGet(hdrs, "Error-Code") != "200" {
			lastErr = fmt.Errorf("%s: Error-Code=%s (HTTP %d)", url, hdrGet(hdrs, "Error-Code"), status)
			continue
		}
		if len(data) > 40 && bytes.HasPrefix(data, []byte("001")) {
			lastErr = errors.New(url + ": 动态算法载荷但探测未成功")
			continue
		}
		algoID, _, err := DecodeAlgoID(data)
		if err != nil {
			lastErr = fmt.Errorf("%s: 解析算法载荷失败: %v", url, err)
			continue
		}
		ci, err := newCipher(algoID)
		if err != nil {
			lastErr = fmt.Errorf("%s: %v", url, err)
			continue
		}
		c.rebaseToPortal(url)
		c.setCipherAndFamily(algoID, "静态算法", ci)
		return nil
	}
	return lastErr
}

var redactPasswdRe = regexp.MustCompile(`<passwd>.*?</passwd>`)

func (c *Client) postXML(url, xmlBody string) (string, error) {
	return c.postXMLWithTimeout(url, xmlBody, 12*time.Second, 30*time.Second, 5)
}

func (c *Client) postXMLWithTimeout(url, xmlBody string, dialTimeout, rwTimeout time.Duration, maxRetries int) (string, error) {
	c.mu.Lock()
	ci := c.cipher
	aid := c.algoID
	cid := c.clientID
	c.mu.Unlock()
	if ci == nil {
		return "", errors.New("cipher 未初始化")
	}
	enc, err := ci.Encrypt([]byte(xmlBody))
	if err != nil {
		return "", err
	}
	if isDebugMode() {
		redacted := redactPasswdRe.ReplaceAllString(xmlBody, "<passwd>***</passwd>")
		_ = os.WriteFile("zsm_plain.log", append([]byte(redacted), '\n', '-', '\n'), 0600)
	}
	headers := append([][2]string{
		{"Algo-ID", aid},
		{"Client-ID", cid},
		{"CDC-Checksum", fmt.Sprintf("%x", md5.Sum([]byte(enc)))},
	}, c.cdcHeaders()...)
	status, hdrs, data, err := c.rawHTTPWithRetry(url, headers, []byte(enc), dialTimeout, rwTimeout, maxRetries)
	if err != nil {
		return "", err
	}
	ec := hdrGet(hdrs, "Error-Code")
	if status != 200 || ec != "0" {
		return "", c.formatServerError(status, ec, data, ci)
	}
	body := strings.TrimSpace(string(data))
	if body == "" {
		return "", nil
	}
	plain, err := ci.Decrypt(body)
	if err != nil {
		if isDebugMode() {
			_ = os.WriteFile("zsm_resp_fail.bin", data, 0600)
		}
		return "", err
	}
	return string(plain), nil
}

func xmlRequest(fields string) string {
	return "<?xml version=\"1.0\" encoding=\"utf-8\"?><request>\n" + fields + "\n</request>"
}

func (c *Client) GetTicket() error {
	c.mu.Lock()
	turl := c.ticketURL
	mac := c.mac
	uip := c.userIP
	cid := c.clientID
	ostag := c.ostag
	hname := c.hostName
	c.mu.Unlock()

	xmlStr := xmlRequest(fmt.Sprintf(
		`<ostag>%s</ostag>
<local-time>%s</local-time>
<gwip>%s</gwip>
<mac>%s</mac>
<ipv6></ipv6>
<ipv4>%s</ipv4>
<client-id>%s</client-id>
<user-agent>%s</user-agent>
<host-name>%s</host-name>`,
		xmlEscape(ostag), time.Now().Format("2006-01-02 15:04:05"), xmlEscape(c.gwIP()), xmlEscape(mac),
		xmlEscape(uip), xmlEscape(cid), UserAgent, xmlEscape(hname)))
	respXML, err := c.postXML(turl, xmlStr)
	if err != nil {
		return fmt.Errorf("取票失败: %v", err)
	}
	t := extractTag(respXML, "ticket")
	if t == "" {
		return errors.New("响应中无 ticket: " + respXML)
	}
	c.mu.Lock()
	c.ticket = t
	c.mu.Unlock()
	c.logf("INFO", "ticket", "ticket: %s", t)
	return nil
}

// QueryState 认证前查询状态
func (c *Client) QueryState() {
	c.mu.Lock()
	surl := c.stateURL
	t := c.ticket
	cid := c.clientID
	c.mu.Unlock()
	if surl == "" {
		return
	}
	xmlStr := xmlRequest(fmt.Sprintf(
		`<local-time>%s</local-time>
<ticket>%s</ticket>
<client-id>%s</client-id>
<user-agent>%s</user-agent>`,
		time.Now().Format("2006-01-02 15:04:05"), xmlEscape(t), xmlEscape(cid), UserAgent))
	_, _ = c.postXML(surl, xmlStr)
}

func (c *Client) Login() error {
	c.mu.Lock()
	aurl := c.authURL
	t := c.ticket
	cid := c.clientID
	c.mu.Unlock()
	xmlStr := xmlRequest(fmt.Sprintf(
		`<local-time>%s</local-time>
<ticket>%s</ticket>
<passwd>%s</passwd>
<userid>%s</userid>
<client-id>%s</client-id>
<user-agent>%s</user-agent>`,
		time.Now().Format("2006-01-02 15:04:05"), xmlEscape(t), xmlEscape(c.pass), xmlEscape(c.user),
		xmlEscape(cid), UserAgent))
	respXML, err := c.postXML(aurl, xmlStr)
	if err != nil {
		return fmt.Errorf("认证失败: %v", err)
	}
	keepURL := extractTag(respXML, "keep-url")
	termURL := extractTag(respXML, "term-url")
	keepRetry := 300
	if v := extractTag(respXML, "keep-retry"); v != "" {
		m := 0
		if _, err := fmt.Sscanf(v, "%d", &m); err == nil && m > 0 {
			keepRetry = m * 60
		}
	}
	if keepURL == "" {
		return errors.New("登录响应无 keep-url: " + respXML)
	}
	c.mu.Lock()
	c.keepURL = keepURL
	c.termURL = termURL
	c.keepRetry = keepRetry
	c.mu.Unlock()
	return nil
}

func (c *Client) Heartbeat() error {
	c.mu.Lock()
	c.helloCount++
	hc := c.helloCount
	t := c.ticket
	cid := c.clientID
	kurl := c.keepURL
	authT := c.authTime
	mac := c.mac
	uip := c.userIP
	c.mu.Unlock()

	xmlStr := xmlRequest(fmt.Sprintf(
		`<local-time>%s</local-time>
<excheck-args><hello>%d</hello><conn>%d</conn></excheck-args>
<mac>%s</mac>
<ipv6></ipv6>
<ipv4>%s</ipv4>
<ticket>%s</ticket>
<client-id>%s</client-id>
<user-agent>%s</user-agent>`,
		time.Now().Format("2006-01-02 15:04:05"),
		hc, int(time.Since(authT).Seconds()),
		xmlEscape(mac), xmlEscape(uip), xmlEscape(t), xmlEscape(cid), UserAgent))
	respXML, err := c.postXMLWithTimeout(kurl, xmlStr, 5*time.Second, 10*time.Second, 2)
	if err != nil {
		return err
	}
	interval := extractTag(respXML, "interval")
	n := 0
	_, _ = fmt.Sscanf(interval, "%d", &n)
	if n >= 10 {
		c.mu.Lock()
		c.keepRetry = n
		c.mu.Unlock()
	}
	return nil
}

// saveSession 持久化会话 (密钥/ticket/term-url/IP) → session.txt
func (c *Client) saveSession() {
	c.mu.Lock()
	ci := c.cipher
	aid := c.algoID
	cid := c.clientID
	t := c.ticket
	turl := c.termURL
	uip, aip := c.userIP, c.acIP
	c.mu.Unlock()

	if t == "" {
		return
	}
	switch v := ci.(type) {
	case *dynAesCipher:
		lines := []string{
			"mode=dynaes",
			"algoID=" + aid,
			"clientID=" + cid,
			"ticket=" + t,
			"termURL=" + turl,
			"userIP=" + uip,
			"acIP=" + aip,
			"key1=" + hex.EncodeToString(v.key1),
			"iv=" + hex.EncodeToString(v.iv),
		}
		_ = os.WriteFile(sessionFile, []byte(strings.Join(lines, "\n")), 0600)
	case *gmsmCipher:
		lines := []string{
			"mode=static",
			"algoID=" + aid,
			"clientID=" + cid,
			"ticket=" + t,
			"termURL=" + turl,
			"userIP=" + uip,
			"acIP=" + aip,
		}
		_ = os.WriteFile(sessionFile, []byte(strings.Join(lines, "\n")), 0600)
	default:
		// dllCipher 会话密钥依赖内存 DLL 态，清除旧记录以免误用
		_ = os.Remove(sessionFile)
	}
}

func readSessionKV() map[string]string {
	b, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil
	}
	kv := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if p := strings.SplitN(strings.TrimSpace(ln), "=", 2); len(p) == 2 {
			kv[p[0]] = p[1]
		}
	}
	return kv
}

// termOldSession 启动时清理自己上次遗留的会话 (reason=2)
func (c *Client) termOldSession() {
	kv := readSessionKV()
	if kv == nil {
		return
	}
	defer os.Remove(sessionFile)

	urlStr := kv["termURL"]
	if urlStr == "" {
		_, _, _, _, urlStr = c.getEndpointURLs()
	}
	if urlStr == "" || kv["ticket"] == "" {
		return
	}
	mode := kv["mode"]
	if mode == "" {
		mode = "dynaes" // 兼容旧格式 session.txt
	}
	var old Cipher
	switch mode {
	case "dynaes":
		k1, e1 := hex.DecodeString(kv["key1"])
		iv, e2 := hex.DecodeString(kv["iv"])
		if e1 != nil || e2 != nil || len(k1) != 32 || len(iv) != 16 {
			return
		}
		old = &dynAesCipher{key1: k1, iv: iv}
	case "static":
		ci, err := newCipher(kv["algoID"])
		if err != nil {
			return
		}
		old = ci
	default:
		return
	}
	if ack, err := c.postTerm(urlStr, kv["algoID"], kv["clientID"], old, kv["ticket"], 2); err != nil {
		c.logf("INFO", "term", "[term] 清理旧会话: %v", err)
	} else if ack {
		c.logf("INFO", "term", "[term] 清理旧会话 OK (reason=2)")
	} else {
		c.logf("INFO", "term", "[term] 已发送旧会话清理 (服务端未回包/正常)")
	}
}

func (c *Client) postTerm(urlStr, algoID, clientID string, ci Cipher, ticket string, reason int) (bool, error) {
	xmlStr := xmlRequest(fmt.Sprintf(
		`<reason>%d</reason>
<local-time>%s</local-time>
<ticket>%s</ticket>
<client-id>%s</client-id>
<user-agent>%s</user-agent>`,
		reason, time.Now().Format("2006-01-02 15:04:05"), xmlEscape(ticket), xmlEscape(clientID), UserAgent))
	enc, err := ci.Encrypt([]byte(xmlStr))
	if err != nil {
		return false, err
	}
	headers := append([][2]string{
		{"Algo-ID", algoID},
		{"Client-ID", clientID},
		{"CDC-Checksum", fmt.Sprintf("%x", md5.Sum([]byte(enc)))},
	}, c.cdcHeaders()...)
	sent, status, hdrs, err := c.rawHTTPPostTerm(urlStr, headers, []byte(enc), 2*time.Second, 1500*time.Millisecond)
	if !sent {
		return false, err
	}
	if err != nil {
		// 部分校园网注销请求一经送达 BRAS 便直接切断会话/静默不回包，按正常下线处理
		return false, nil
	}
	ec := hdrGet(hdrs, "Error-Code")
	if status != 200 || (ec != "" && ec != "0" && ec != "200") {
		return false, fmt.Errorf("EC=%s HTTP=%d", ec, status)
	}
	return true, nil
}

// Logout 主动注销当前会话 (幂等、清理本地凭据状态，对服务端静默/断流快速容错)
func (c *Client) Logout() {
	c.mu.Lock()
	ci := c.cipher
	aid := c.algoID
	cid := c.clientID
	t := c.ticket
	turl := c.termURL
	kurl := c.keepURL
	c.cipher = nil
	c.ticket = ""
	c.termURL = ""
	c.keepURL = ""
	c.keepRetry = 0
	c.helloCount = 0
	c.authTime = time.Time{}
	c.lastHeartbeat = time.Time{}
	c.algoID = zeroAlgoID
	c.algoFamily = ""
	c.mu.Unlock()

	defer func() {
		if cl, ok := ci.(interface{ Close() }); ok {
			cl.Close()
		}
	}()

	if t != "" {
		_ = os.Remove(sessionFile)
	}
	if turl == "" && kurl != "" {
		turl = portalRoot(kurl) + "/term.cgi"
	}
	if ci == nil || t == "" || turl == "" {
		return
	}
	ack, err := c.postTerm(turl, aid, cid, ci, t, 1)
	if err != nil {
		c.logf("WARN", "term", "[term] 注销请求未送达 (%v)，已清理本地会话", err)
	} else if ack {
		c.logf("INFO", "term", "[term] 已注销当前会话 (reason=1 主动下线)")
	} else {
		c.logf("INFO", "term", "[term] 已发送注销请求 (服务端未回包/链路已断开，属正常下线行为)")
	}
}

// Preflight 官方认证前必走: 并发 GET detect.html (+ 同主机未命中时 GET index.cgi)
func (c *Client) Preflight() {
	c.mu.Lock()
	tURL := c.ticketURL
	pfHost := c.preflightHost
	ecHost := c.econfigHost
	uip, aip := c.userIP, c.acIP
	c.mu.Unlock()

	if tURL == "" {
		return
	}
	portalHost := hostOf(tURL)
	if pfHost == portalHost {
		return
	}
	base := tURL
	if i := strings.Index(base, "/ticket.cgi"); i >= 0 {
		base = base[:i]
	}
	paths := []string{base + "/detect.html"}
	if portalHost != ecHost {
		paths = append(paths, base+"/index.cgi?wlanuserip="+uip+"&wlanacip="+aip)
	}
	pfCtx, pfCancel := context.WithTimeout(c.activeCtx(), 1500*time.Millisecond)
	defer pfCancel()
	var wg sync.WaitGroup
	for _, p := range paths {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			for attempt := 0; attempt < 2; attempt++ {
				if attempt > 0 {
					if !sleepCtx(pfCtx, gatewayRetryDelays[0]) {
						return
					}
				}
				req, err := http.NewRequestWithContext(pfCtx, "GET", u, nil)
				if err != nil {
					return
				}
				resp, _, err := c.doKeepAlive(req)
				if err != nil || resp == nil || !isTransientGatewayStatus(resp.StatusCode) || resp.Header.Get("Error-Code") != "" {
					break
				}
			}
		}(p)
	}
	wg.Wait()
	c.mu.Lock()
	c.preflightHost = portalHost
	c.mu.Unlock()
}

func (c *Client) resetSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCipherLocked()
	c.algoID = zeroAlgoID
	c.algoFamily = ""
	c.ticket = ""
	c.ticketURL = ""
	c.authURL = ""
	c.stateURL = ""
	c.keepURL = ""
	c.termURL = ""
	c.portalPage = ""
	c.portalNode = ""
	c.clusterServers = nil
	c.econfigHost = ""
	c.preflightHost = ""
	c.cachedGWKey = ""
	c.cachedGWIP = ""
	c.deadPortals = nil
	clearDNSRaceCache()
	c.srcIP = nil
	c.srcIfIndex = 0
	c.nicName = ""
	c.nicGateway = ""
	c.nicDNS = nil
	c.userIP = ""
	c.acIP = ""
	c.helloCount = 0
	c.lastHeartbeat = time.Time{}
	c.school = c.cmdSchool
	c.domain = c.cmdDomain
	c.area = c.cmdArea
}

func (c *Client) bindSourceByUserIP() {
	c.mu.Lock()
	alreadyBound := c.srcIP != nil && c.srcIfIndex > 0
	uip := c.userIP
	c.mu.Unlock()
	if alreadyBound || uip == "" {
		return
	}
	target := net.ParseIP(uip)
	if target == nil || target.To4() == nil {
		return
	}
	adapters := EnumerateAdapters()
	if a, ok := findAdapterByIP(adapters, target.To4().String()); ok {
		ip4 := net.ParseIP(a.IP4).To4()
		c.mu.Lock()
		c.srcIP = append(net.IP(nil), ip4...)
		c.srcIfIndex = a.IfIndex
		c.nicName = a.Name
		c.nicGateway = a.Gateway
		c.nicDNS = append([]string(nil), a.DNSServers...)
		if a.MAC != "" {
			c.mac = a.MAC
		}
		c.mu.Unlock()
		c.setHTTPClient(boundClientWithNIC(ip4, a.IfIndex, a.DNSServers, 10*time.Second, 30*time.Second))
		return
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, f := range ifaces {
		addrs, err := f.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(target) {
				ip4 := ipn.IP.To4()
				c.mu.Lock()
				c.srcIP = append(net.IP(nil), ip4...)
				c.srcIfIndex = uint32(f.Index)
				c.nicName = f.Name
				if isValidMAC(f.HardwareAddr) {
					c.mac = strings.ReplaceAll(strings.ToUpper(f.HardwareAddr.String()), ":", "-")
				}
				c.mu.Unlock()
				c.setHTTPClient(boundClientWithNIC(ip4, uint32(f.Index), nil, 10*time.Second, 30*time.Second))
				return
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func matchErrorCode(msgLower, code string) bool {
	return strings.Contains(msgLower, "error-code="+code+" ") ||
		strings.Contains(msgLower, "error-code="+code+"|") ||
		strings.Contains(msgLower, "error-code="+code+")") ||
		strings.HasSuffix(msgLower, "error-code="+code)
}

// isFatalAuthErr 判定是否属于账号/密码/欠费/多终端等不可盲目自动重试的致命认证错误
func isFatalAuthErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if matchErrorCode(msg, "100") || matchErrorCode(msg, "101") || matchErrorCode(msg, "105") ||
		matchErrorCode(msg, "110") || matchErrorCode(msg, "201") {
		return true
	}
	return strings.Contains(msg, "请输入密码") || strings.Contains(msg, "请输入校园网账号")
}

// isNoNetworkDetectErr 判定是否属于开机/切换 Wi-Fi 时物理网卡尚无可用 IP 或暂未捕获校园网的暂态错误
func isNoNetworkDetectErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "未检测到可用的物理网络接口") ||
		strings.Contains(msg, "未检测到需要认证的校园网接口")
}

// isInstantOfflineHeartbeatErr 判定心跳失败是否源于服务端会话失效或 AC 强制认证劫持（无需苦等 3 次重试）
func isInstantOfflineHeartbeatErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if matchErrorCode(msg, "12") || matchErrorCode(msg, "300") || matchErrorCode(msg, "1") ||
		matchErrorCode(msg, "2") || matchErrorCode(msg, "105") || matchErrorCode(msg, "101") || matchErrorCode(msg, "100") {
		return true
	}
	if strings.Contains(msg, "http=301") || strings.Contains(msg, "http=302") || strings.Contains(msg, "http=307") {
		return true
	}
	if strings.Contains(msg, "error-code= ") &&
		(strings.Contains(msg, "<html") || strings.Contains(msg, "<!doctype") || strings.Contains(msg, "wlanuserip=") || strings.Contains(msg, "index.cgi")) {
		return true
	}
	return false
}

func (c *Client) effectiveWatchdogURL() string {
	if strings.TrimSpace(c.watchdogURL) != "" {
		return strings.TrimSpace(c.watchdogURL)
	}
	return "http://27.159.75.27/"
}

func (c *Client) effectiveWatchdogInterval() time.Duration {
	if c.watchdogInterval > 0 {
		return c.watchdogInterval
	}
	return 8 * time.Second
}

func probeHealthTarget(ctx context.Context, cl *http.Client, target string) (captive bool, loc string, err error) {
	pCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pCtx, "GET", target, nil)
	if err != nil {
		return false, "", err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return false, "", err
	}
	loc, isCap := extractCaptiveRedirect(resp, target)
	resp.Body.Close()
	return isCap, loc, nil
}

func (c *Client) watchBaseNIC() (uint32, string) {
	c.mu.Lock()
	ifIdx := c.srcIfIndex
	localIP := ""
	if c.srcIP != nil && c.srcIP.To4() != nil {
		localIP = c.srcIP.To4().String()
	}
	c.mu.Unlock()
	return ifIdx, localIP
}

func checkNICChanged(baseIfIndex uint32, baseLocalIP string) (changed bool, reason string) {
	if baseIfIndex == 0 || baseLocalIP == "" {
		return false, ""
	}
	exists, isUp, ips := queryInterfaceIPv4Fast(baseIfIndex)
	if !exists || !isUp || len(ips) == 0 {
		return true, fmt.Sprintf("物理网卡 (#%d) 已断开或失去 IPv4 地址", baseIfIndex)
	}
	for _, ip := range ips {
		if ip == baseLocalIP {
			return false, ""
		}
	}
	return true, fmt.Sprintf("物理网卡 IP 变更: %s → %s", baseLocalIP, ips[0])
}

func snapshotPhysicalIPs(pinnedIf uint32) string {
	return snapshotPhysicalIPsFast(pinnedIf)
}

func sleepReconnectBackoff(ctx context.Context, total time.Duration, pinnedIf uint32) bool {
	if total <= 0 {
		return ctx.Err() == nil
	}
	baseSig := snapshotPhysicalIPs(pinnedIf)
	deadline := time.Now().Add(total)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return ctx.Err() == nil
		}
		wait := 2 * time.Second
		if rem < wait {
			wait = rem
		}
		if !sleepCtx(ctx, wait) {
			return false
		}
		if time.Until(deadline) <= 0 {
			return ctx.Err() == nil
		}
		if cur := snapshotPhysicalIPs(pinnedIf); cur != "" && cur != baseSig {
			return true
		}
	}
}

// sleepWithWatchdog 在心跳周期或已在线空闲期间每 8s 巡检一次网卡与零 DNS 强制认证探测，发现掉线立即唤醒重连
func (c *Client) sleepWithWatchdog(ctx context.Context, total time.Duration, baseIfIndex uint32, baseLocalIP string) (ok bool, captiveDrop bool, reason string) {
	if total <= 0 {
		return ctx.Err() == nil, false, ""
	}
	interval := c.effectiveWatchdogInterval()
	deadline := time.Now().Add(total)
	target := c.effectiveWatchdogURL()

	c.mu.Lock()
	srcIP := append(net.IP(nil), c.srcIP...)
	ifIdx := c.srcIfIndex
	dns := append([]string(nil), c.nicDNS...)
	c.mu.Unlock()

	probeCl := boundClientWithNIC(srcIP, ifIdx, dns, 2500*time.Millisecond, 3*time.Second)
	if tr, ok2 := probeCl.Transport.(*http.Transport); ok2 && tr != nil {
		defer tr.CloseIdleConnections()
	}

	probeErrs := 0
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return ctx.Err() == nil, false, ""
		}
		wait := interval
		if rem < wait {
			wait = rem
		}
		if !sleepCtx(ctx, wait) {
			return false, false, ctx.Err().Error()
		}
		if time.Until(deadline) <= 0 {
			return ctx.Err() == nil, false, ""
		}
		if chg, why := checkNICChanged(baseIfIndex, baseLocalIP); chg {
			return false, true, why
		}
		isCap, loc, perr := probeHealthTarget(ctx, probeCl, target)
		if isCap {
			return false, true, "检测到校园网强制认证重定向 (" + portalRoot(loc) + ")"
		}
		if perr != nil && c.watchdogURL == "" {
			// 默认外网探测 IP 偶发异常时追加阿里云 DNS IP 二次核验，避免单点抖动误报
			isCap2, loc2, perr2 := probeHealthTarget(ctx, probeCl, "http://223.5.5.5/")
			if isCap2 {
				return false, true, "检测到校园网强制认证重定向 (" + portalRoot(loc2) + ")"
			}
			perr = perr2
		}
		if perr != nil {
			probeErrs++
			if probeErrs >= 2 {
				return false, false, fmt.Sprintf("直连网络探针连续不可达: %v", perr)
			}
			continue
		}
		probeErrs = 0
	}
}

func isTransientTicketOrNetErr(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	for _, kw := range []string{"timeout", "connection refused", "bad gateway", "eof", "reset", "no route", "unreachable"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func (c *Client) runNegotiateAndTicket(ctx context.Context) (dAlgo, dTicket int64, err error) {
	maxCycles := ticketRetryMaxCycles
	if maxCycles <= 0 {
		maxCycles = 1
	}
	budget := ticketRetryBudget
	if budget <= 0 {
		budget = 30 * time.Second
	}
	retryCtx, retryCancel := context.WithTimeout(ctx, budget)
	defer retryCancel()

	c.mu.Lock()
	prevCtx := c.runCtx
	c.runCtx = retryCtx
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.runCtx = prevCtx
		c.mu.Unlock()
	}()

	var lastErr error
	lastMarkedDead := false
	for cycle := 0; cycle < maxCycles; cycle++ {
		if ctx.Err() != nil {
			return dAlgo, dTicket, ctx.Err()
		}
		if retryCtx.Err() != nil {
			break
		}
		if cycle > 0 {
			wait := 500 * time.Millisecond
			hasHealthy := false
			if lastMarkedDead {
				for _, u := range c.candidateTicketURLs() {
					if !c.isPortalDead(u) {
						hasHealthy = true
						break
					}
				}
			}
			if !hasHealthy && len(ticketRetryBackoffs) > 0 {
				idx := minInt(cycle-1, len(ticketRetryBackoffs)-1)
				wait = ticketRetryBackoffs[idx]
			}
			if dl, ok := retryCtx.Deadline(); ok {
				rem := time.Until(dl)
				if rem <= 0 {
					break
				}
				if wait > rem {
					wait = rem
				}
			}
			c.logf("WARN", "negotiate", "[重试] 第 %d 轮: 等待 %dms 后重新协商取票", cycle, int(wait.Milliseconds()))
			if !sleepCtx(retryCtx, wait) {
				if ctx.Err() != nil {
					return dAlgo, dTicket, ctx.Err()
				}
				break
			}
		}
		lastMarkedDead = false

		c.setState(StateConnecting, "negotiate", "")
		tSub := time.Now()
		if err := c.negotiateAlgo(); err != nil {
			if ctx.Err() != nil {
				return dAlgo, dTicket, ctx.Err()
			}
			c.logf("INFO", "negotiate", "[动态算法] 探测失败, 回退静态算法: %v", err)
			if serr := c.negotiateAlgoStatic(); serr != nil {
				if ctx.Err() != nil {
					return dAlgo, dTicket, ctx.Err()
				}
				return dAlgo, dTicket, fmt.Errorf("动态与静态算法均失败: %v", serr)
			}
		}
		dAlgo = time.Since(tSub).Milliseconds()
		c.mu.Lock()
		aidLog := c.algoID
		famLog := c.algoFamily
		needMAC := c.srcIP == nil || c.srcIP.String() != c.userIP || c.mac == ""
		uipForMAC := c.userIP
		c.mu.Unlock()
		c.logf("INFO", "negotiate", "算法: %s (%s)", aidLog, famLog)
		if needMAC {
			if m := ifaceMACByIP(uipForMAC); m != "" {
				c.mu.Lock()
				c.mac = strings.ReplaceAll(m, ":", "-")
				c.mu.Unlock()
			}
		}

		c.setState(StateConnecting, "ticket", "")
		tTick0 := time.Now()
		c.Preflight()
		if err := c.GetTicket(); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return dAlgo, dTicket, ctx.Err()
			}
			if isFatalAuthErr(err) {
				return dAlgo, dTicket, err
			}
			c.logf("WARN", "ticket", "[取票失败] %v", err)
			if isTransientTicketOrNetErr(err) {
				turl, _, _, _, _ := c.getEndpointURLs()
				if turl != "" {
					c.markPortalDead(turl)
					lastMarkedDead = true
				}
			}
			continue
		}
		dTicket = time.Since(tTick0).Milliseconds()
		return dAlgo, dTicket, nil
	}
	if lastErr != nil {
		return dAlgo, dTicket, lastErr
	}
	if ctx.Err() != nil {
		return dAlgo, dTicket, ctx.Err()
	}
	return dAlgo, dTicket, errors.New("取票重试超出预算")
}

func (c *Client) runOnce(ctx context.Context, force bool) (loggedIn bool, err error) {
	t0 := time.Now()
	c.resetSession()
	c.setState(StateConnecting, "detect", "")
	indexURL, err := c.DetectContext(ctx)
	dDetect := time.Since(t0).Milliseconds()
	if err != nil {
		return false, err
	}
	if indexURL == "" && !force {
		c.mu.Lock()
		c.lastTimings = PhaseTimings{DetectMs: dDetect, TotalMs: dDetect}
		c.mu.Unlock()
		c.logf("INFO", "detect", "网络已在线，无需认证 (%dms) (如需重新认证: 退出本程序后重跑, 或加 -force 参数)", dDetect)
		return false, nil
	}
	if indexURL == "" && force {
		c.mu.Lock()
		curNICIP := c.userIP
		if c.srcIP != nil && c.srcIP.To4() != nil {
			curNICIP = c.srcIP.To4().String()
		}
		c.mu.Unlock()

		if b, err := os.ReadFile(`C:\Program Files (x86)\Chinatelecom_GDPortal\Config\ConnectSetting.ini`); err == nil {
			s := string(b)
			getIni := func(k string) string {
				for _, ln := range strings.Split(s, "\n") {
					ln = strings.TrimSpace(ln)
					if strings.HasPrefix(ln, k+"=") {
						return strings.TrimSpace(ln[len(k)+1:])
					}
				}
				return ""
			}
			uip, aip := getIni("wlanuserip"), getIni("wlanacip")
			if uip != "" && aip != "" {
				if curNICIP != "" && uip != curNICIP {
					c.logf("INFO", "detect", "[force] 忽略过期官方配置 (%s != 当前网卡 %s)", uip, curNICIP)
				} else {
					c.setSessionIPs(uip, aip, false)
					indexURL = "http://enet.10000.gd.cn:10001/?wlanuserip=" + uip + "&wlanacip=" + aip
					if tick := getIni("tickUrl"); tick != "" {
						indexURL = tick
					}
					c.logf("INFO", "detect", "[force] 使用官方配置会话参数: %s %s", uip, aip)
				}
			}
		}
		if indexURL == "" {
			_, curAC := c.getSessionIPs()
			if cached := loadPortalCache(curAC); len(cached) > 0 {
				base := cached[0]
				if strings.Contains(base, "wlanuserip=") && strings.Contains(base, "wlanacip=") {
					cachedUIP, _, _, _, _, _ := extractSessionParams(base)
					if curNICIP == "" || cachedUIP == "" || cachedUIP == curNICIP {
						indexURL = base
					}
				} else if kv := readSessionKV(); kv != nil && kv["userIP"] != "" && kv["acIP"] != "" {
					if curNICIP == "" || kv["userIP"] == curNICIP {
						indexURL = strings.TrimRight(base, "/") + "/?wlanuserip=" + kv["userIP"] + "&wlanacip=" + kv["acIP"]
					}
				}
			}
		}
		if indexURL == "" {
			// 纯无官方配置或配置已过期时使用当前物理网卡 IP + 域名调度探针，自动随省中心调度与并发 DNS 解析
			if curNICIP != "" {
				indexURL = "http://enet.10000.gd.cn:10001/?wlanuserip=" + curNICIP
			}
		}
		if indexURL == "" {
			return false, errors.New("-force 模式未找到可用会话参数，请先断开或指定账号重新触发认证")
		}
		c.logf("INFO", "detect", "[force] 跳过在线检测, 强制重新认证")
	}
	c.logf("INFO", "detect", "检测到需要认证: %s", indexURL)
	if err := c.extractIndexParams(indexURL); err != nil {
		// 若首页是 10001 调度跳转无 wlanacip，仍继续由 walkRedirectAndConfig 获取完整参数
		uip, _, pnode, sc, dm, ar := extractSessionParams(indexURL)
		if uip == "" {
			return false, err
		}
		c.setSessionIPs(uip, "", false)
		c.setPortalNode(pnode, false)
		c.applyDiscoveredSchool(sc, dm, ar)
	}
	c.bindSourceByUserIP()
	uipLog, aipLog := c.getSessionIPs()
	c.logf("INFO", "config", "userIP=%s acIP=%s", uipLog, aipLog)

	c.setState(StateConnecting, "config", "")
	tCfg0 := time.Now()
	if _, serr := os.Stat(sessionFile); serr == nil {
		var cfgWG sync.WaitGroup
		cfgWG.Add(2)
		go func() {
			defer cfgWG.Done()
			c.GetEConfig(indexURL)
		}()
		go func() {
			defer cfgWG.Done()
			c.termOldSession()
		}()
		cfgWG.Wait()
	} else {
		c.GetEConfig(indexURL)
	}
	dConfig := time.Since(tCfg0).Milliseconds()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	turlLog, _, _, _, _ := c.getEndpointURLs()
	scLog, dmLog, arLog := c.getSchoolInfo()
	c.logf("INFO", "config", "ticketURL: %s (school=%s domain=%s area=%s)", turlLog, scLog, dmLog, arLog)

	var dAlgo, dTicket, dLogin int64
	for loginAttempt := 0; loginAttempt < 2; loginAttempt++ {
		if loginAttempt > 0 {
			if !sleepCtx(ctx, 500*time.Millisecond) {
				return false, ctx.Err()
			}
		}
		dAlgo, dTicket, err = c.runNegotiateAndTicket(ctx)
		if err != nil {
			return false, err
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		c.logf("INFO", "ticket", "ticket OK")
		if isQueryStateMode() {
			c.QueryState()
		}
		c.setState(StateConnecting, "login", "")
		tLogin0 := time.Now()
		err := c.Login()
		dLogin = time.Since(tLogin0).Milliseconds()
		if err == nil {
			break
		}
		if ctx.Err() != nil || isFatalAuthErr(err) || loginAttempt >= 1 {
			return false, err
		}
		lowErr := strings.ToLower(err.Error())
		if strings.Contains(lowErr, "timeout") || strings.Contains(lowErr, "bad gateway") || strings.Contains(lowErr, "connection refused") {
			_, aurlCur, _, _, _ := c.getEndpointURLs()
			c.markPortalDead(aurlCur)
		}
		c.mu.Lock()
		c.closeCipherLocked()
		c.ticket = ""
		c.mu.Unlock()
		c.logf("WARN", "login", "[登录重试] 遇到瞬态异常 (%v)，正在切换节点重协商登录...", err)
	}
	dTotal := time.Since(t0).Milliseconds()
	c.mu.Lock()
	c.lastTimings = PhaseTimings{
		DetectMs:    dDetect,
		ConfigMs:    dConfig,
		NegotiateMs: dAlgo,
		TicketMs:    dTicket,
		LoginMs:     dLogin,
		TotalMs:     dTotal,
	}
	c.authTime = time.Now()
	c.helloCount = 0
	kurl := c.keepURL
	kretry := c.keepRetry
	scDone, dmDone, arDone := c.school, c.domain, c.area
	turlDone := c.ticketURL
	authCB := c.onAuthSuccess
	c.mu.Unlock()

	if authCB != nil {
		authCB()
	}
	c.logf("INFO", "login", "登录成功 keepURL=%s 心跳周期=%ds (学校=%s 域名=%s 区号=%s)",
		kurl, kretry, scDone, dmDone, arDone)
	c.logf("INFO", "login", "[耗时] 探测 %dms | 配置 %dms | 协商 %dms | 取票 %dms | 登录 %dms | 总计 %dms",
		dDetect, dConfig, dAlgo, dTicket, dLogin, dTotal)
	c.savePortalCache(turlDone)
	c.saveSession()
	c.saveProfile()
	c.setState(StateConnected, "online", "")

	if !sleepCtx(ctx, 1500*time.Millisecond) {
		c.Logout()
		return true, ctx.Err()
	}
	failCount := 0
	for {
		if ctx.Err() != nil {
			c.Logout()
			return true, ctx.Err()
		}
		if err := c.Heartbeat(); err != nil {
			if ctx.Err() != nil {
				c.Logout()
				return true, ctx.Err()
			}
			if isInstantOfflineHeartbeatErr(err) {
				c.logf("ERROR", "keepalive", "检测到会话已失效或被认证网关拦截 (%v) → 立即重新认证", err)
				return true, errors.New("会话已失效，立即重认证")
			}
			failCount++
			c.logf("WARN", "keepalive", "心跳失败(%d/3): %v", failCount, err)
			if failCount >= 3 {
				c.logf("ERROR", "keepalive", "判定掉线 → 立即重新认证")
				return true, errors.New("心跳连续失败，需要重认证")
			}
			if !sleepCtx(ctx, 2*time.Second) {
				c.Logout()
				return true, ctx.Err()
			}
			continue
		}
		wasFailed := failCount > 0
		failCount = 0
		c.mu.Lock()
		c.lastHeartbeat = time.Now()
		hc := c.helloCount
		kr := c.keepRetry
		c.mu.Unlock()
		ifIdx, localIP := c.watchBaseNIC()
		c.setState(StateConnected, "online", "")
		if wasFailed {
			c.logf("INFO", "keepalive", "心跳恢复 OK %s", time.Now().Format("15:04:05"))
		} else if hc == 1 {
			c.logf("INFO", "keepalive", "首次心跳 OK %s", time.Now().Format("15:04:05"))
		} else if hc%6 == 0 {
			c.logf("INFO", "keepalive", "心跳 OK × %d %s", hc, time.Now().Format("15:04:05"))
		}
		ok, capDrop, why := c.sleepWithWatchdog(ctx, time.Duration(kr)*time.Second, ifIdx, localIP)
		if ctx.Err() != nil {
			c.Logout()
			return true, ctx.Err()
		}
		if !ok {
			if capDrop {
				c.logf("WARN", "keepalive", "离线哨兵检测掉线: %s → 立即重新认证", why)
				return true, errors.New(why)
			}
			c.logf("WARN", "keepalive", "离线哨兵探测异常 (%s) → 提前执行心跳核验", why)
		}
	}
}

func (c *Client) watchAlreadyOnline(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ifIdx, localIP := c.watchBaseNIC()
		ok, _, why := c.sleepWithWatchdog(ctx, 24*time.Hour, ifIdx, localIP)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !ok {
			return errors.New(why)
		}
	}
}

func (c *Client) Run(force bool) error {
	return c.RunContext(context.Background(), force)
}

func (c *Client) RunContext(ctx context.Context, force bool) error {
	return c.RunWatchContext(ctx, force, false)
}

// RunWatchContext 执行认证与保活循环；watchOnline=true 时即使启动前已在线也持续 8s 巡检，掉线秒级自愈重连
func (c *Client) RunWatchContext(ctx context.Context, force, watchOnline bool) error {
	c.mu.Lock()
	c.runCtx = ctx
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.runCtx = nil
		c.mu.Unlock()
	}()
	everLoggedIn := false
	firstReconnect := true
	runForce := force
	backoff := 3 * time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		loggedIn, err := c.runOnce(ctx, runForce)
		if loggedIn {
			everLoggedIn = true
			firstReconnect = true
			runForce = false
			backoff = 3 * time.Second
		}
		if err == nil {
			if !watchOnline {
				return nil
			}
			everLoggedIn = true
			firstReconnect = true
			runForce = false
			backoff = 3 * time.Second
			c.setState(StateConnected, "already-online", "")
			c.logf("INFO", "keepalive", "已开启在线离线哨兵 (每 %ds 自动巡检，掉线将自动重连)", int(c.effectiveWatchdogInterval().Seconds()))
			err = c.watchAlreadyOnline(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !everLoggedIn {
			if watchOnline && isNoNetworkDetectErr(err) && !isFatalAuthErr(err) {
				runForce = false
				c.setState(StateConnecting, "reconnect", err.Error())
				c.logf("INFO", "detect", "等待物理网卡就绪并关联校园网 (%v)...", err)
				if !sleepReconnectBackoff(ctx, backoff, c.getPinnedIfIndex()) {
					return ctx.Err()
				}
				if backoff < 10*time.Second {
					if backoff == 3*time.Second {
						backoff = 5 * time.Second
					} else {
						backoff = 10 * time.Second
					}
				}
				continue
			}
			return err
		}
		runForce = false
		c.setState(StateConnecting, "reconnect", err.Error())
		if firstReconnect {
			firstReconnect = false
			c.logf("WARN", "reconnect", "[重连] 检测到网络/会话中断 (%v)，立即重新认证...", err)
			continue
		}
		c.logf("WARN", "reconnect", "[重连] 认证/网络恢复失败 (%v)，%ds 后重试...", err, int(backoff.Seconds()))
		if !sleepReconnectBackoff(ctx, backoff, c.getPinnedIfIndex()) {
			return ctx.Err()
		}
		if backoff < 10*time.Second {
			if backoff == 3*time.Second {
				backoff = 5 * time.Second
			} else {
				backoff = 10 * time.Second
			}
		}
	}
}

func resolvePinnedIfIndex(spec string) uint32 {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0
	}
	if n, err := strconv.Atoi(spec); err == nil && n > 0 {
		return uint32(n)
	}
	for _, a := range EnumerateAdapters() {
		if strings.EqualFold(a.Name, spec) || strings.Contains(strings.ToLower(a.Name), strings.ToLower(spec)) || a.IP4 == spec {
			return a.IfIndex
		}
	}
	return 0
}

func main() {
	daemonFlag := flag.Bool("daemon", false, "内部: 启动本地回环守护服务 (供现代 GUI 调用)")
	doctorFlag := flag.Bool("doctor", false, "只读网络体检 (物理网卡 / TUN 绕过 / DNS / 省中心节点)")
	issueFlag := flag.Bool("issue", false, "输出脱敏后的 GitHub Issue Markdown 诊断报告")
	ifaceFlag := flag.String("iface", "", "指定物理出口网卡 (ifIndex / 网卡名 / IPv4)")
	dllworker := flag.Bool("dllworker", false, "内部: 常驻算法DLL隔离工作进程")
	dllpe := flag.String("dllpe", "", "内部: 算法DLL镜像文件")
	dllkey := flag.String("dllkey", "", "内部: 会话 keyhex")
	dllmode := flag.String("dllmode", "", "内部: enc|dec")
	dllin := flag.String("dllin", "", "内部: 输入文件")
	user := flag.String("u", "", "账号(手机号/学号)")
	pass := flag.String("p", "", "密码")
	school := flag.String("school", "", "学校ID(CDC-SchoolId, 可留空自动发现)")
	domain := flag.String("domain", "", "学校域名(CDC-Domain, 可留空自动发现)")
	area := flag.String("area", "", "区号(CDC-Area, 可留空自动发现)")
	ostagOverride := flag.String("ostag", "", "覆盖 ostag (默认读注册表取 Windows Build 号)")
	force := flag.Bool("force", false, "跳过在线检测, 强制重新认证")
	qState := flag.Bool("query-state", false, "登录前发送 state.cgi 状态查询")
	dbg := flag.Bool("debug", false, "开启调试落盘与详细日志 (zsm_wire.log / zsm_plain.log / [dll])")
	flag.Parse()
	setDebugMode(*dbg)
	setQueryStateMode(*qState)

	if *dllworker {
		if err := runDllWorker(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "dllworker:", err)
			os.Exit(4)
		}
		return
	}
	if *dllpe != "" {
		dllVerbose = true
		img, err := os.ReadFile(*dllpe)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dllpe:", err)
			os.Exit(4)
		}
		key := *dllkey
		if len(img) < 2 || img[0] != 'M' || img[1] != 'Z' {
			_, _, _, kh, _, pe2, ex := solvePayload(img)
			if ex != nil {
				fmt.Fprintln(os.Stderr, "载荷解析:", ex)
				os.Exit(4)
			}
			img, key = pe2, kh
		}
		input, err := os.ReadFile(*dllin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dllin:", err)
			os.Exit(4)
		}
		out, err := dllRun(img, key, *dllmode, input)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dllalgo:", err)
			os.Exit(4)
		}
		fmt.Println(out)
		return
	}
	if *daemonFlag {
		if err := runDaemon(); err != nil {
			fmt.Fprintln(os.Stderr, "daemon:", err)
			os.Exit(5)
		}
		return
	}
	if *doctorFlag || *issueFlag {
		pinned := resolvePinnedIfIndex(*ifaceFlag)
		rep := RunNetworkDoctor(context.Background(), pinned)
		if *issueFlag {
			cl := NewClient(*user, *pass, *school, *domain, *area)
			fmt.Println(BuildIssueMarkdown(cl.Snapshot(), rep.ProxyEnv, rep.Adapters, &rep, nil, nil, *user, *pass))
			return
		}
		fmt.Printf("=== GDPortal 网络体检 (%s) ===\n", rep.GeneratedAt)
		fmt.Printf("代理/TUN 模式: %s\n", rep.ProxyEnv.BypassMode)
		for _, ck := range rep.Checks {
			fmt.Printf("[%s] %s (%dms): %s\n", strings.ToUpper(ck.Status), ck.Name, ck.RTTMs, ck.Detail)
			if ck.Advice != "" {
				fmt.Printf("       建议: %s\n", ck.Advice)
			}
		}
		return
	}
	if *user == "" || *pass == "" {
		fmt.Println("广东电信天翼校园网轻量认证客户端 (gdportal-lite)")
		fmt.Println("用法: gdportal-lite -u 账号 -p 密码 [-school ID] [-domain xxx] [-area xxx]")
		fmt.Println("      不填 school/domain/area 时将自动通过各校 AC/省中心调度网关获取")
		flag.PrintDefaults()
		os.Exit(1)
	}
	cl := NewClient(*user, *pass, *school, *domain, *area)
	cl.pinnedIfIndex = resolvePinnedIfIndex(*ifaceFlag)
	if *ostagOverride != "" {
		cl.ostag = *ostagOverride
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	logoutDone := make(chan struct{})
	go func() {
		select {
		case s := <-sigCh:
			fmt.Printf("\n收到退出信号 (%v) — 注销当前会话...\n", s)
			cl.Logout()
			os.Exit(0)
		case <-logoutDone:
		}
	}()
	if err := cl.Run(*force); err != nil {
		close(logoutDone)
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(2)
	}
	close(logoutDone)
}
