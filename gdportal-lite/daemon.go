package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// daemonConfig 存储到 %LOCALAPPDATA%\GDPortal\config.json，密码仅以 Windows DPAPI 密文落盘
type daemonConfig struct {
	Account          string `json:"account"`
	EncryptedPass    string `json:"encryptedPassword,omitempty"`
	RememberPassword bool   `json:"rememberPassword"`
	ManualOverride   bool   `json:"manualOverride"`
	School           string `json:"school"`
	Domain           string `json:"domain"`
	Area             string `json:"area"`
	PinnedIfIndex    uint32 `json:"pinnedIfIndex"`
	Theme            string `json:"theme"`
	CloseToTray      bool   `json:"closeToTray"`
	AutoConnect      bool   `json:"autoConnect"`
	AutoStart        bool   `json:"autoStart"`
	ForceReauth      bool   `json:"forceReauth"`
	PrivacyMode      bool   `json:"privacyMode"`
	DebugWire        bool   `json:"debugWire"`
	QueryState       bool   `json:"queryState"`
}

type publicConfig struct {
	Account          string `json:"account"`
	HasSavedPassword bool   `json:"hasSavedPassword"`
	RememberPassword bool   `json:"rememberPassword"`
	ManualOverride   bool   `json:"manualOverride"`
	School           string `json:"school"`
	Domain           string `json:"domain"`
	Area             string `json:"area"`
	PinnedIfIndex    uint32 `json:"pinnedIfIndex"`
	Theme            string `json:"theme"`
	CloseToTray      bool   `json:"closeToTray"`
	AutoConnect      bool   `json:"autoConnect"`
	AutoStart        bool   `json:"autoStart"`
	ForceReauth      bool   `json:"forceReauth"`
	PrivacyMode      bool   `json:"privacyMode"`
	DebugWire        bool   `json:"debugWire"`
	QueryState       bool   `json:"queryState"`
}

func (c daemonConfig) toPublic() publicConfig {
	return publicConfig{
		Account:          c.Account,
		HasSavedPassword: c.EncryptedPass != "",
		RememberPassword: c.RememberPassword,
		ManualOverride:   c.ManualOverride,
		School:           c.School,
		Domain:           c.Domain,
		Area:             c.Area,
		PinnedIfIndex:    c.PinnedIfIndex,
		Theme:            c.Theme,
		CloseToTray:      c.CloseToTray,
		AutoConnect:      c.AutoConnect,
		AutoStart:        c.AutoStart,
		ForceReauth:      c.ForceReauth,
		PrivacyMode:      c.PrivacyMode,
		DebugWire:        c.DebugWire,
		QueryState:       c.QueryState,
	}
}

func appDataConfigDir() string {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, "GDPortal")
	}
	if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
		return filepath.Join(cfg, "GDPortal")
	}
	return "."
}

func daemonConfigPath() string {
	return filepath.Join(appDataConfigDir(), "config.json")
}

func defaultDaemonConfig() daemonConfig {
	return daemonConfig{
		Theme:            "dark",
		CloseToTray:      true,
		RememberPassword: true,
		PrivacyMode:      true,
	}
}

func loadDaemonConfig() daemonConfig {
	cfg := defaultDaemonConfig()
	raw, err := os.ReadFile(daemonConfigPath())
	if err == nil {
		_ = json.Unmarshal(raw, &cfg)
		if cfg.Theme == "" {
			cfg.Theme = "dark"
		}
		return cfg
	}
	// 首次运行尝试从旧 profile.txt 继承学校参数
	if prof, err2 := os.ReadFile(profileFile); err2 == nil {
		for _, ln := range strings.Split(string(prof), "\n") {
			if pp := strings.SplitN(strings.TrimSpace(ln), "=", 2); len(pp) == 2 {
				switch pp[0] {
				case "school":
					cfg.School = pp[1]
				case "domain":
					cfg.Domain = pp[1]
				case "area":
					cfg.Area = pp[1]
				}
			}
		}
	}
	return cfg
}

func saveDaemonConfig(cfg daemonConfig) error {
	dir := appDataConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(daemonConfigPath(), raw, 0600)
}

type daemonServer struct {
	opMu       sync.Mutex
	mu         sync.Mutex
	token      string
	cfg        daemonConfig
	client     *Client
	diag       *DiagHub
	cancelRun  context.CancelFunc
	runDone    chan struct{}
	lastDoctor *DoctorReport
	srv        *http.Server
	shutdownCh chan struct{}
}

func newDaemonServer() *daemonServer {
	tokBytes := make([]byte, 32)
	_, _ = rand.Read(tokBytes)
	diag := NewDiagHub()
	cfg := loadDaemonConfig()
	setDebugMode(cfg.DebugWire)
	setQueryStateMode(cfg.QueryState)
	cl := NewClient(cfg.Account, "", cfg.School, cfg.Domain, cfg.Area)
	cl.diag = diag
	cl.setPinnedIfIndex(cfg.PinnedIfIndex)
	if cfg.DebugWire {
		cl.logf("INFO", "init", "调试模式已启用")
	}
	return &daemonServer{
		token:      hex.EncodeToString(tokBytes),
		cfg:        cfg,
		client:     cl,
		diag:       diag,
		shutdownCh: make(chan struct{}),
	}
}

func (d *daemonServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimSpace(r.Header.Get("X-GDPortal-Token"))
		if tok == "" {
			if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
				tok = strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))
			}
		}
		if len(tok) != len(d.token) || subtle.ConstantTimeCompare([]byte(tok), []byte(d.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *daemonServer) snapshotLocked() SessionSnapshot {
	snap := d.client.Snapshot()
	adapters := EnumerateAdapters()
	proxyEnv := DetectProxyEnv(adapters)
	snap.ProxyBypassed = true
	snap.BypassMode = proxyEnv.BypassMode
	return snap
}

func (d *daemonServer) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adapters := EnumerateAdapters()
	proxyEnv := DetectProxyEnv(adapters)
	d.mu.Lock()
	snap := d.client.Snapshot()
	snap.ProxyBypassed = true
	snap.BypassMode = proxyEnv.BypassMode
	pubCfg := d.cfg.toPublic()
	doc := d.lastDoctor
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  appVersion,
		"session":  snap,
		"config":   pubCfg,
		"adapters": adapters,
		"proxyEnv": proxyEnv,
		"doctor":   doc,
		"logs":     d.diag.Logs(),
		"wires":    d.diag.Wires(),
	})
}

func (d *daemonServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	subID, ch := d.diag.Subscribe()
	defer d.diag.Unsubscribe(subID)

	// 立即推送一次当前快照
	d.mu.Lock()
	initSnap := d.snapshotLocked()
	d.mu.Unlock()
	if b, err := json.Marshal(map[string]any{"type": "state", "data": initSnap}); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			if b, err := json.Marshal(ev); err == nil {
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			}
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

type connectReq struct {
	Account          string `json:"account"`
	Password         string `json:"password"`
	UseSavedPassword bool   `json:"useSavedPassword"`
	RememberPassword bool   `json:"rememberPassword"`
	Force            bool   `json:"force"`
	OneShotForce     bool   `json:"oneShotForce,omitempty"`
	ManualOverride   bool   `json:"manualOverride"`
	School           string `json:"school"`
	Domain           string `json:"domain"`
	Area             string `json:"area"`
	PinnedIfIndex    uint32 `json:"pinnedIfIndex"`
	DebugWire        bool   `json:"debugWire"`
	QueryState       bool   `json:"queryState"`
}

func (d *daemonServer) stopActiveLocked(detachOld bool) {
	cancel := d.cancelRun
	done := d.runDone
	d.cancelRun = nil
	d.runDone = nil
	if detachOld && d.client != nil {
		d.client.detached.Store(true)
	}
	if cancel != nil {
		cancel()
	}
	if done != nil {
		d.mu.Unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		d.mu.Lock()
	}
}

func (d *daemonServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req connectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效请求参数"})
		return
	}
	acct := strings.TrimSpace(req.Account)
	if acct == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请输入校园网账号"})
		return
	}

	d.opMu.Lock()
	defer d.opMu.Unlock()

	d.mu.Lock()
	pass := req.Password
	if pass == "" && req.UseSavedPassword && d.cfg.EncryptedPass != "" {
		if acct != d.cfg.Account {
			d.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "已切换账号，请重新输入新账号的密码"})
			return
		}
		if dec, err := DPAPIUnprotect(d.cfg.EncryptedPass); err == nil {
			pass = string(dec)
		}
	}
	if pass == "" {
		d.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请输入密码"})
		return
	}

	d.stopActiveLocked(true)

	// 认证成功前仅立即持久化非凭据类参数；若同一已保存账号取消了“记住密码”，立即清除旧密文
	if acct == d.cfg.Account && !req.RememberPassword {
		d.cfg.RememberPassword = false
		d.cfg.EncryptedPass = ""
	}
	d.cfg.ManualOverride = req.ManualOverride
	d.cfg.School = strings.TrimSpace(req.School)
	d.cfg.Domain = strings.TrimSpace(req.Domain)
	d.cfg.Area = strings.TrimSpace(req.Area)
	d.cfg.PinnedIfIndex = req.PinnedIfIndex
	if !req.OneShotForce {
		d.cfg.ForceReauth = req.Force
	}
	d.cfg.DebugWire = req.DebugWire
	d.cfg.QueryState = req.QueryState
	_ = saveDaemonConfig(d.cfg)

	setDebugMode(req.DebugWire)
	setQueryStateMode(req.QueryState)

	school, domain, area := "", "", ""
	if req.ManualOverride {
		school, domain, area = d.cfg.School, d.cfg.Domain, d.cfg.Area
	}
	cl := NewClient(acct, pass, school, domain, area)
	cl.diag = d.diag
	cl.setPinnedIfIndex(req.PinnedIfIndex)
	rememberPwd := req.RememberPassword
	cl.onAuthSuccess = func() {
		if cl.detached.Load() {
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.client != cl || cl.detached.Load() {
			return
		}
		d.cfg.Account = acct
		d.cfg.RememberPassword = rememberPwd
		if rememberPwd {
			if enc, err := DPAPIProtect([]byte(pass)); err == nil {
				d.cfg.EncryptedPass = enc
			}
		} else {
			d.cfg.EncryptedPass = ""
		}
		_ = saveDaemonConfig(d.cfg)
	}
	cl.setState(StateConnecting, "detect", "")
	d.client = cl

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.cancelRun = cancel
	d.runDone = done
	d.mu.Unlock()

	go func() {
		defer close(done)
		if err := cl.RunWatchContext(ctx, req.Force, true); err != nil {
			if cl.detached.Load() {
				return
			}
			if ctx.Err() == nil {
				cl.setState(StateError, "error", err.Error())
				cl.logf("ERROR", "auth", "%v", err)
			} else {
				cl.setState(StateDisconnected, "", "")
			}
			return
		}
		if cl.detached.Load() {
			return
		}
		if ctx.Err() == nil {
			cl.setState(StateConnected, "already-online", "")
		} else {
			cl.setState(StateDisconnected, "", "")
		}
	}()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *daemonServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()

	d.mu.Lock()
	cl := d.client
	if cl != nil {
		cl.setState(StateDisconnecting, "logout", "")
	}
	d.stopActiveLocked(false)
	d.mu.Unlock()
	if cl != nil {
		cl.Logout()
		cl.setState(StateDisconnected, "", "")
		cl.logf("INFO", "term", "已断开并清理本地认证会话")
		cl.detached.Store(true)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *daemonServer) handleAdapters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adapters := EnumerateAdapters()
	proxyEnv := DetectProxyEnv(adapters)
	writeJSON(w, http.StatusOK, map[string]any{
		"adapters": adapters,
		"proxyEnv": proxyEnv,
	})
}

func (d *daemonServer) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d.mu.Lock()
	pinned := d.cfg.PinnedIfIndex
	d.mu.Unlock()
	rep := RunNetworkDoctor(r.Context(), pinned)
	d.mu.Lock()
	d.lastDoctor = &rep
	d.mu.Unlock()
	d.diag.AddLog("INFO", "doctor", fmt.Sprintf("网络体检完成 (%d 项检查)", len(rep.Checks)))
	writeJSON(w, http.StatusOK, rep)
}

func (d *daemonServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var patch map[string]any
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效设置载荷"})
		return
	}
	d.mu.Lock()
	if v, ok := patch["theme"].(string); ok && (v == "dark" || v == "light" || v == "system") {
		d.cfg.Theme = v
	}
	if v, ok := patch["closeToTray"].(bool); ok {
		d.cfg.CloseToTray = v
	}
	if v, ok := patch["autoConnect"].(bool); ok {
		d.cfg.AutoConnect = v
	}
	if v, ok := patch["autoStart"].(bool); ok {
		d.cfg.AutoStart = v
	}
	if v, ok := patch["forceReauth"].(bool); ok {
		d.cfg.ForceReauth = v
	}
	if v, ok := patch["privacyMode"].(bool); ok {
		d.cfg.PrivacyMode = v
	}
	if v, ok := patch["debugWire"].(bool); ok {
		d.cfg.DebugWire = v
		setDebugMode(v)
	}
	if v, ok := patch["queryState"].(bool); ok {
		d.cfg.QueryState = v
		setQueryStateMode(v)
	}
	if v, ok := patch["manualOverride"].(bool); ok {
		d.cfg.ManualOverride = v
	}
	if v, ok := patch["school"].(string); ok {
		d.cfg.School = strings.TrimSpace(v)
	}
	if v, ok := patch["domain"].(string); ok {
		d.cfg.Domain = strings.TrimSpace(v)
	}
	if v, ok := patch["area"].(string); ok {
		d.cfg.Area = strings.TrimSpace(v)
	}
	if v, ok := patch["pinnedIfIndex"].(float64); ok && v >= 0 {
		d.cfg.PinnedIfIndex = uint32(v)
		if d.client != nil {
			d.client.setPinnedIfIndex(d.cfg.PinnedIfIndex)
		}
	}
	if v, ok := patch["rememberPassword"].(bool); ok {
		d.cfg.RememberPassword = v
		if !v {
			d.cfg.EncryptedPass = ""
		}
	}
	_ = saveDaemonConfig(d.cfg)
	pub := d.cfg.toPublic()
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": pub})
}

func (d *daemonServer) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	adapters := EnumerateAdapters()
	proxyEnv := DetectProxyEnv(adapters)
	d.mu.Lock()
	snap := d.client.Snapshot()
	snap.ProxyBypassed = true
	snap.BypassMode = proxyEnv.BypassMode
	doc := d.lastDoctor
	secAcct := d.cfg.Account
	pinnedIdx := d.cfg.PinnedIfIndex
	secUser, secPass := d.client.user, d.client.pass
	if saved, err := DPAPIUnprotect(d.cfg.EncryptedPass); err == nil && len(saved) > 0 && secPass == "" {
		secPass = string(saved)
	}
	d.mu.Unlock()

	if doc == nil {
		rep := RunNetworkDoctor(r.Context(), pinnedIdx)
		doc = &rep
	}
	logs := d.diag.Logs()
	wires := d.diag.Wires()
	md := BuildIssueMarkdown(snap, proxyEnv, adapters, doc, logs, wires, secAcct, secUser, secPass)
	js := BuildIssueJSON(snap, proxyEnv, adapters, doc, logs, wires, secAcct, secUser, secPass)
	ts := time.Now().Format("20060102-150405")
	writeJSON(w, http.StatusOK, map[string]any{
		"markdown": md,
		"json":     string(js),
		"mdName":   "gdportal-issue-" + ts + ".md",
		"jsonName": "gdportal-diag-" + ts + ".json",
	})
}

func (d *daemonServer) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d.diag.Clear()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *daemonServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	go func() {
		d.opMu.Lock()
		d.mu.Lock()
		d.stopActiveLocked(true)
		d.mu.Unlock()
		d.opMu.Unlock()
		select {
		case <-d.shutdownCh:
		default:
			close(d.shutdownCh)
		}
		if d.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = d.srv.Shutdown(ctx)
			cancel()
		}
	}()
}

func runDaemon() error {
	setDaemonMode(true)
	d := newDaemonServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", d.authMiddleware(d.handleState))
	mux.HandleFunc("/api/events", d.authMiddleware(d.handleEvents))
	mux.HandleFunc("/api/connect", d.authMiddleware(d.handleConnect))
	mux.HandleFunc("/api/disconnect", d.authMiddleware(d.handleDisconnect))
	mux.HandleFunc("/api/adapters", d.authMiddleware(d.handleAdapters))
	mux.HandleFunc("/api/doctor", d.authMiddleware(d.handleDoctor))
	mux.HandleFunc("/api/settings", d.authMiddleware(d.handleSettings))
	mux.HandleFunc("/api/issue", d.authMiddleware(d.handleIssue))
	mux.HandleFunc("/api/logs/clear", d.authMiddleware(d.handleLogsClear))
	mux.HandleFunc("/api/shutdown", d.authMiddleware(d.handleShutdown))

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	d.srv = &http.Server{Handler: mux}

	// 打印单行 JSON 握手信息供桌面外壳连接，此后不再向 stdout 输出其它内容
	addr := ln.Addr().(*net.TCPAddr)
	handshake, _ := json.Marshal(map[string]any{
		"port":    addr.Port,
		"token":   d.token,
		"pid":     os.Getpid(),
		"version": appVersion,
	})
	fmt.Println(string(handshake))

	// 若父进程关闭 stdin 管道（例如意外崩溃），自动注销下线并退出
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
		}
		d.opMu.Lock()
		d.mu.Lock()
		d.stopActiveLocked(true)
		d.mu.Unlock()
		d.opMu.Unlock()
		_ = d.srv.Close()
		select {
		case <-d.shutdownCh:
		default:
			close(d.shutdownCh)
		}
	}()

	err = d.srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
