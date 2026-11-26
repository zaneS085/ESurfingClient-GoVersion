package main

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RedirectHop 记录单跳 AC / Portal 重定向详情
type RedirectHop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Kind     string `json:"kind"` // "302", "meta-refresh", "js-redirect", "econfig", "html", "error"
	Location string `json:"location,omitempty"`
	School   string `json:"school,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Area     string `json:"area,omitempty"`
	RTTMs    int64  `json:"rttMs"`
}

// EConfigInfo 为 index.cgi 解析出的门户端节点配置
type EConfigInfo struct {
	TicketURL      string
	AuthURL        string
	StateURL       string
	QueryURL       string
	ClusterServers []string
}

var (
	metaTagRe        = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	metaEquivRefresh = regexp.MustCompile(`(?is)\bhttp-equiv\s*=\s*(?:"refresh"|'refresh'|refresh\b)`)
	metaContentAttr  = regexp.MustCompile(`(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	metaContentURL   = regexp.MustCompile(`(?is)\burl\s*=\s*([^\s;'"]+)`)
	jsRedirectRe     = regexp.MustCompile(`(?is)(?:window|top|self|document)?\.?location(?:\.href)?\s*=\s*["']([^"']+)["']`)
	jsReplaceRe      = regexp.MustCompile(`(?is)(?:window|top|self|document)?\.?location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)`)
	clusterServersRe = regexp.MustCompile(`(?is)<server-clusters\b[^>]*\bservers\s*=\s*["']([^"']+)["']`)
)

// extractRedirectFromHTML 从各校 AC 返回的 HTML 中提取 Meta Refresh / JS 跳转目标
func extractRedirectFromHTML(body, baseURL string) (target, kind string) {
	raw := ""
	for _, tag := range metaTagRe.FindAllString(body, 16) {
		if !metaEquivRefresh.MatchString(tag) {
			continue
		}
		cm := metaContentAttr.FindStringSubmatch(tag)
		if len(cm) < 4 {
			continue
		}
		contentVal := html.UnescapeString(cm[1] + cm[2] + cm[3])
		if um := metaContentURL.FindStringSubmatch(contentVal); len(um) >= 2 {
			raw = um[1]
			kind = "meta-refresh"
			break
		}
	}
	if raw == "" {
		for _, re := range []*regexp.Regexp{jsReplaceRe, jsRedirectRe} {
			if m := re.FindStringSubmatch(body); len(m) >= 2 {
				cand := html.UnescapeString(strings.TrimSpace(m[1]))
				if cand != "" && !strings.HasPrefix(cand, "#") && !strings.HasPrefix(strings.ToLower(cand), "javascript:") {
					raw = cand
					kind = "js-redirect"
					break
				}
			}
		}
	}
	raw = strings.Trim(raw, " \t\r\n'\"")
	if raw == "" {
		return "", ""
	}
	if baseURL != "" {
		if bu, err := url.Parse(baseURL); err == nil {
			if ru, err2 := bu.Parse(raw); err2 == nil {
				return ru.String(), kind
			}
		}
	}
	return raw, kind
}

// extractQueryCI 按大小写无关解析 URL Query 参数
func extractQueryCI(rawURL string) map[string]string {
	res := map[string]string{}
	u, err := url.Parse(rawURL)
	if err != nil {
		return res
	}
	for k, vals := range u.Query() {
		if len(vals) > 0 && vals[0] != "" {
			res[strings.ToLower(k)] = strings.TrimSpace(vals[0])
		}
	}
	return res
}

// extractSessionParams 从不同学校 URL 参数中提取核心字段 (兼容 wlanuserip/userip、wlanacip/nasip 等命名)
func extractSessionParams(rawURL string) (userIP, acIP, portalNode, school, domain, area string) {
	q := extractQueryCI(rawURL)
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := q[k]; v != "" {
				return v
			}
		}
		return ""
	}
	userIP = first("wlanuserip", "userip", "user_ip", "ip")
	acIP = first("wlanacip", "wlanacname", "nasip", "acip", "basip")
	portalNode = first("portal_node", "portalnode")
	school = first("schoolid", "school_id", "school")
	domain = first("domain")
	area = first("area", "areacode")
	return
}

// parseEConfig 解析 index.cgi 页面嵌入的 EConfig 配置与 server-clusters 集群列表
func parseEConfig(body string) EConfigInfo {
	var info EConfigInfo
	start := strings.Index(body, "<!--//config.campus.js.chinatelecom.com")
	end := strings.Index(body, "//config.campus.js.chinatelecom.com-->")
	if start < 0 || end <= start {
		return info
	}
	cfg := body[start:end]
	cfg = strings.NewReplacer("&width=0", "", "&adtype=0", "").Replace(cfg)
	info.TicketURL = extractTag(cfg, "ticket-url")
	info.AuthURL = extractTag(cfg, "auth-url")
	info.StateURL = extractTag(cfg, "state-url")
	info.QueryURL = extractTag(cfg, "query-url")
	if m := clusterServersRe.FindStringSubmatch(cfg); len(m) >= 2 {
		for _, part := range strings.Split(m[1], ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if !strings.Contains(p, "://") {
				p = "http://" + p
			}
			info.ClusterServers = appendUniqueStr(info.ClusterServers, portalRoot(p))
		}
	}
	return info
}

func appendUniqueStr(list []string, val string) []string {
	val = strings.TrimSpace(val)
	if val == "" {
		return list
	}
	for _, existing := range list {
		if existing == val {
			return list
		}
	}
	return append(list, val)
}

var defaultDispatcherURLs = []string{
	"http://enet.10000.gd.cn:10001/",
	"http://125.88.59.131:10001/",
	"http://61.140.12.23:10001/",
}

func (c *Client) absorbHeaders(h http.Header) (school, domain, area string) {
	firstHdr := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(h.Get(k)); v != "" {
				return v
			}
		}
		return ""
	}
	school = firstHdr("schoolid", "CDC-SchoolId", "school-id")
	domain = firstHdr("domain", "CDC-Domain")
	area = firstHdr("area", "CDC-Area")
	c.applyDiscoveredSchool(school, domain, area)
	return
}

func (c *Client) applyDiscoveredSchool(school, domain, area string) {
	c.mu.Lock()
	if school != "" && c.cmdSchool == "" {
		c.school = school
	}
	if domain != "" && c.cmdDomain == "" {
		c.domain = domain
	}
	if area != "" && c.cmdArea == "" {
		c.area = area
	}
	c.mu.Unlock()
}

func (c *Client) needAutoSchool() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmdSchool == "" && c.school == "" {
		return true
	}
	if c.cmdDomain == "" && c.domain == "" {
		return true
	}
	if c.cmdArea == "" && c.area == "" {
		return true
	}
	return false
}

func buildQueryURL(base, userIP, acIP string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	if userIP != "" && q.Get("wlanuserip") == "" {
		q.Set("wlanuserip", userIP)
	}
	if acIP != "" && q.Get("wlanacip") == "" {
		q.Set("wlanacip", acIP)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// walkRedirectAndConfig 多跳追踪 AC/门户跳转链，自动吸收 schoolid/domain/area/clusterServers 与 EConfig
func (c *Client) walkRedirectAndConfig(startURL string) {
	ctx := c.activeCtx()
	cfgCl, cleanup := c.fastConfigClient()
	defer cleanup()

	var hops []RedirectHop
	curURL := startURL
	triedSibling := false
	for step := 0; step < 6 && curURL != ""; step++ {
		if ctx.Err() != nil {
			break
		}
		if uip, aip, pnode, sc, dm, ar := extractSessionParams(curURL); true {
			c.setSessionIPs(uip, aip, true)
			c.setPortalNode(pnode, false)
			c.applyDiscoveredSchool(sc, dm, ar)
		}

		tReq := time.Now()
		var resp *http.Response
		var body []byte
		var err error
		for attempt := 0; attempt <= 2; attempt++ {
			if attempt > 0 {
				if !sleepCtx(ctx, gatewayRetryDelays[attempt-1]) {
					err = ctx.Err()
					break
				}
			}
			req, reqErr := http.NewRequestWithContext(ctx, "GET", curURL, nil)
			if reqErr != nil {
				err = reqErr
				break
			}
			scHdr, _, _ := c.getSchoolInfo()
			if scHdr != "" {
				req.Header.Set("CDC-SchoolId", scHdr)
			}
			resp, body, err = c.doWithClient(cfgCl, req, "close")
			if err != nil || resp == nil || !isTransientGatewayStatus(resp.StatusCode) || resp.Header.Get("Error-Code") != "" {
				break
			}
		}
		rtt := time.Since(tReq).Milliseconds()
		if err != nil || resp == nil {
			hops = append(hops, RedirectHop{URL: curURL, Kind: "error", RTTMs: rtt})
			c.markPortalDead(curURL)
			if ctx.Err() != nil {
				break
			}
			c.logf("WARN", "config", "请求 %s 失败 (%dms): %v", SanitizeDiagnosticText(curURL), rtt, err)
			if !triedSibling && step > 0 && strings.Contains(strings.ToLower(curURL), ":7001") {
				triedSibling = true
				uipCur, aipCur := c.getSessionIPs()
				siblingURL := ""
				for _, cb := range loadPortalCache(aipCur) {
					if !c.isPortalDead(cb) && strings.Contains(strings.ToLower(cb), ":7001") {
						siblingURL = strings.TrimRight(cb, "/") + "/index.cgi?wlanuserip=" + uipCur + "&wlanacip=" + aipCur
						break
					}
				}
				if siblingURL != "" {
					c.logf("INFO", "config", "切换健康备用节点获取配置: %s", portalRoot(siblingURL))
					curURL = siblingURL
					continue
				}
			}
			if !c.needAutoSchool() && strings.Contains(strings.ToLower(curURL), ":7001") {
				c.logf("INFO", "config", "跳过无响应配置节点 %s，直接故障转移到备用认证节点", portalRoot(curURL))
			}
			break
		}

		sc, dm, ar := c.absorbHeaders(resp.Header)
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		hop := RedirectHop{
			URL:      curURL,
			Status:   resp.StatusCode,
			Location: loc,
			School:   sc,
			Domain:   dm,
			Area:     ar,
			RTTMs:    rtt,
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			nextURL := loc
			if bu, pe := url.Parse(curURL); pe == nil {
				if ru, pe2 := bu.Parse(loc); pe2 == nil {
					nextURL = ru.String()
				}
			}
			hop.Kind = fmt.Sprintf("%d", resp.StatusCode)
			hops = append(hops, hop)
			c.setPortalPage(nextURL, false)
			if strings.Contains(strings.ToLower(nextURL), ":7001") {
				c.addClusterServers(portalRoot(nextURL))
			}
			curURL = nextURL
			continue
		}

		bodyStr := string(body)
		if info := parseEConfig(bodyStr); info.TicketURL != "" || info.AuthURL != "" || len(info.ClusterServers) > 0 {
			hop.Kind = "econfig"
			hops = append(hops, hop)
			idxHost := hostOf(curURL)
			var tURL, aURL, sURL string
			if info.TicketURL != "" && hostOf(info.TicketURL) == idxHost {
				tURL = info.TicketURL
			}
			if info.AuthURL != "" && hostOf(info.AuthURL) == idxHost {
				aURL = info.AuthURL
			}
			if info.StateURL != "" && hostOf(info.StateURL) == idxHost {
				sURL = info.StateURL
			}
			c.setEConfigResult(idxHost, curURL, tURL, aURL, sURL, info.ClusterServers)
			break
		}

		if nextURL, kind := extractRedirectFromHTML(bodyStr, curURL); nextURL != "" {
			hop.Kind = kind
			hop.Location = nextURL
			hops = append(hops, hop)
			c.setPortalPage(nextURL, false)
			if strings.Contains(strings.ToLower(nextURL), ":7001") {
				c.addClusterServers(portalRoot(nextURL))
			}
			curURL = nextURL
			continue
		}

		hop.Kind = "html"
		hops = append(hops, hop)
		break
	}
	if c.diag != nil {
		c.diag.SetHops(hops)
	}
}

// autoDiscoverSchool 当 index.cgi 未直接带回 school/domain/area 时，主动向 portal_node / 广东调度网关获取
func (c *Client) autoDiscoverSchool() {
	uip, aip := c.getSessionIPs()
	if !c.needAutoSchool() || uip == "" || aip == "" {
		return
	}
	ctx := c.activeCtx()
	cfgCl, cleanup := c.fastConfigClient()
	defer cleanup()

	var probes []string
	if pnode := c.getPortalNode(); pnode != "" {
		probes = appendUniqueStr(probes, portalRoot(pnode)+"/")
	}
	for _, u := range defaultDispatcherURLs {
		probes = appendUniqueStr(probes, u)
	}
	for _, base := range probes {
		if !c.needAutoSchool() || ctx.Err() != nil {
			break
		}
		target := buildQueryURL(base, uip, aip)
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		resp, body, err := c.doWithClient(cfgCl, req, "close")
		if err != nil || resp == nil {
			continue
		}
		sc, dm, ar := c.absorbHeaders(resp.Header)
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		if loc == "" && resp.StatusCode == 200 {
			loc, _ = extractRedirectFromHTML(string(body), target)
		}
		if loc != "" {
			_, _, pnode, lsc, ldm, lar := extractSessionParams(loc)
			c.setPortalNode(pnode, true)
			c.applyDiscoveredSchool(lsc, ldm, lar)
			if strings.Contains(strings.ToLower(loc), ":7001") {
				c.addClusterServers(portalRoot(loc))
				c.setPortalPage(loc, true)
			}
		}
		if sc != "" || dm != "" || ar != "" {
			curSc, curDm, curAr := c.getSchoolInfo()
			c.logf("INFO", "config", "自动识别学校参数: school=%s domain=%s area=%s (来源 %s)",
				curSc, curDm, curAr, portalRoot(base))
		}
	}
}

func describeErrorCode(ec string) string {
	switch strings.TrimSpace(ec) {
	case "1":
		return "服务端解密或校验失败 (Error-Code=1)"
	case "2":
		return "服务端拒绝旧协议或请求格式无效 (Error-Code=2)"
	case "12":
		return "会话无效/参数不匹配或票据已过期 (Error-Code=12)"
	case "100":
		return "认证失败 (Error-Code=100，请检查账号/密码或学校参数)"
	case "101":
		return "账号不存在或密码错误 (Error-Code=101)"
	case "105":
		return "账号已停机/欠费或未开通校园网 (Error-Code=105)"
	case "110":
		return "终端在线数量已达上限 (Error-Code=110)"
	case "201":
		return "账号已在其他终端在线 (Error-Code=201)"
	case "300":
		return "当前未在线或状态查询返回未登录 (Error-Code=300)"
	default:
		if ec == "" {
			return "网关异常或无 Error-Code 响应"
		}
		return "服务端返回 Error-Code=" + ec
	}
}

// formatServerError 格式化网关/认证错误信息，尝试用当前会话算法解密服务端返回的 XML 错误说明
func (c *Client) formatServerError(status int, ec string, data []byte, ci Cipher) error {
	hint := describeErrorCode(ec)
	if isTransientGatewayStatus(status) && ec == "" {
		hint = fmt.Sprintf("校园网认证网关临时不可用 (HTTP %d Bad Gateway)", status)
	}
	msg := ""
	trimmed := strings.TrimSpace(string(data))
	if ci != nil && trimmed != "" && !strings.HasPrefix(trimmed, "<") {
		if plain, err := ci.Decrypt(trimmed); err == nil {
			pStr := strings.TrimSpace(string(plain))
			for _, tag := range []string{"err-msg", "errmsg", "message", "error-info", "info", "reason", "detail"} {
				if v := extractTag(pStr, tag); v != "" {
					msg = v
					break
				}
			}
			if msg == "" && pStr != "" {
				msg = pStr
			}
		}
	}
	if msg != "" {
		return fmt.Errorf("%s | HTTP=%d Error-Code=%s (%s)", hint, status, ec, SanitizeDiagnosticText(msg, c.pass))
	}
	preview := SanitizeDiagnosticText(string(data[:minInt(len(data), 160)]), c.pass)
	return fmt.Errorf("%s | HTTP=%d Error-Code=%s body=%q", hint, status, ec, preview)
}
