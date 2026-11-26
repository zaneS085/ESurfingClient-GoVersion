package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed core_amd64.gz
var embeddedCoreGZ []byte

//go:embed ui/*
var uiAssetsFS embed.FS

type daemonHandshake struct {
	Port    int    `json:"port"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
	Version string `json:"version"`
}

type CoreManager struct {
	mu           sync.RWMutex
	corePath     string
	coreMode     string
	cmd          *exec.Cmd
	stdinPipe    io.WriteCloser
	daemonURL    string
	daemonToken  string
	uiServer     *http.Server
	uiURL        string
	uiHost       string
	uiOrigin     string
	uiSecret     string
	closeToTray  bool
	theme        string
	onThemeUI    func(theme string)
	onOpenDialog func(defaultName, content string) (string, error)
	stderrRing   bytes.Buffer
}

func NewCoreManager(explicitCore string, onTheme func(string), onSave func(string, string) (string, error)) *CoreManager {
	sec := make([]byte, 16)
	_, _ = rand.Read(sec)
	return &CoreManager{
		corePath:     explicitCore,
		uiSecret:     hex.EncodeToString(sec),
		closeToTray:  true,
		theme:        "dark",
		onThemeUI:    onTheme,
		onOpenDialog: onSave,
	}
}

func localAppDataDir() string {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, "GDPortal")
	}
	if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
		return filepath.Join(cfg, "GDPortal")
	}
	return "."
}

func extractEmbeddedCore() (string, error) {
	if len(embeddedCoreGZ) == 0 {
		return "", errors.New("embedded core_amd64.gz is empty")
	}
	sum := sha256.Sum256(embeddedCoreGZ)
	tag := hex.EncodeToString(sum[:6])
	binDir := filepath.Join(localAppDataDir(), "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	target := filepath.Join(binDir, fmt.Sprintf("gdportal-core-%s.exe", tag))
	if st, err := os.Stat(target); err == nil && st.Size() > 1<<20 {
		return target, nil
	}
	gr, err := gzip.NewReader(bytes.NewReader(embeddedCoreGZ))
	if err != nil {
		return "", err
	}
	defer gr.Close()

	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, gr); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	_ = os.Rename(tmp, target)
	if _, err := os.Stat(target); err == nil {
		return target, nil
	}
	return tmp, nil
}

func (m *CoreManager) resolveCoreBinary() (string, string, error) {
	if m.corePath != "" {
		if _, err := os.Stat(m.corePath); err == nil {
			return m.corePath, "external", nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		adj := filepath.Join(filepath.Dir(exe), "gdportal-lite.exe")
		if _, err2 := os.Stat(adj); err2 == nil {
			return adj, "adjacent", nil
		}
	}
	path, err := extractEmbeddedCore()
	if err != nil {
		return "", "", err
	}
	return path, "embedded", nil
}

func (m *CoreManager) Start() error {
	coreExe, mode, err := m.resolveCoreBinary()
	if err != nil {
		return fmt.Errorf("准备核心组件失败: %w", err)
	}
	m.mu.Lock()
	m.corePath = coreExe
	m.coreMode = mode
	m.mu.Unlock()

	cmd := exec.Command(coreExe, "-daemon")
	cmd.Dir = filepath.Dir(coreExe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动认证核心失败: %w", err)
	}
	m.mu.Lock()
	m.cmd = cmd
	m.stdinPipe = stdin
	m.mu.Unlock()

	go func() {
		_, _ = io.Copy(&m.stderrRing, io.LimitReader(stderr, 16<<10))
	}()

	hsCh := make(chan daemonHandshake, 1)
	errCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		if sc.Scan() {
			var hs daemonHandshake
			if e := json.Unmarshal(sc.Bytes(), &hs); e != nil {
				errCh <- fmt.Errorf("核心握手解析失败: %w (%s)", e, sc.Text())
				return
			}
			hsCh <- hs
			return
		}
		if e := sc.Err(); e != nil {
			errCh <- e
		} else {
			errCh <- errors.New("核心进程提前退出: " + strings.TrimSpace(m.stderrRing.String()))
		}
	}()

	select {
	case hs := <-hsCh:
		m.mu.Lock()
		m.daemonURL = fmt.Sprintf("http://127.0.0.1:%d", hs.Port)
		m.daemonToken = hs.Token
		m.mu.Unlock()
	case e := <-errCh:
		_ = cmd.Process.Kill()
		return e
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		return errors.New("等待认证核心握手超时 (10s)")
	}

	if err := m.startUIServer(); err != nil {
		return err
	}
	m.syncConfigFromDaemon()
	return nil
}

const uiSessionCookie = "gdportal_session"

func (m *CoreManager) tokenMatches(got string) bool {
	m.mu.RLock()
	sec := m.uiSecret
	m.mu.RUnlock()
	if sec == "" || len(got) != len(sec) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(sec)) == 1
}

func (m *CoreManager) hasValidSession(r *http.Request) bool {
	if tok := strings.TrimSpace(r.Header.Get("X-GDPortal-UI-Token")); tok != "" {
		return m.tokenMatches(tok)
	}
	if ck, err := r.Cookie(uiSessionCookie); err == nil && ck != nil {
		return m.tokenMatches(ck.Value)
	}
	return false
}

func (m *CoreManager) isAllowedHostAndOrigin(r *http.Request, isWrite bool) bool {
	m.mu.RLock()
	uiHost := m.uiHost
	uiOrigin := m.uiOrigin
	m.mu.RUnlock()

	if uiHost != "" && !strings.EqualFold(r.Host, uiHost) {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" && uiOrigin != "" {
		if !strings.EqualFold(origin, uiOrigin) {
			return false
		}
	}
	if isWrite {
		if sfs := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); sfs != "" && sfs != "same-origin" && sfs != "none" {
			return false
		}
		if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" && uiOrigin != "" {
			lowRef := strings.ToLower(ref)
			lowOrig := strings.ToLower(uiOrigin)
			if lowRef != lowOrig && !strings.HasPrefix(lowRef, lowOrig+"/") {
				return false
			}
		}
	}
	return true
}

func (m *CoreManager) guardAPI(allowedMethod string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowedMethod != "" && r.Method != allowedMethod {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.hasValidSession(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		isWrite := r.Method != http.MethodGet && r.Method != http.MethodHead
		if !m.isAllowedHostAndOrigin(r, isWrite) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (m *CoreManager) buildUIHandler(proxy *httputil.ReverseProxy, fileSrv http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ui/meta", m.guardAPI(http.MethodGet, m.handleUIMeta))
	mux.HandleFunc("/api/ui/theme", m.guardAPI(http.MethodPost, m.handleUITheme))
	mux.HandleFunc("/api/ui/autostart", m.guardAPI(http.MethodPost, m.handleUIAutoStart))
	mux.HandleFunc("/api/ui/save-file", m.guardAPI(http.MethodPost, m.handleUISaveFile))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/shutdown" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var allowedMethod string
		switch r.URL.Path {
		case "/api/state", "/api/events", "/api/adapters":
			allowedMethod = http.MethodGet
		case "/api/connect", "/api/disconnect", "/api/settings", "/api/logs/clear", "/api/doctor", "/api/issue":
			allowedMethod = http.MethodPost
		default:
			http.NotFound(w, r)
			return
		}
		m.guardAPI(allowedMethod, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/settings" {
				m.handleSettingsProxy(w, r, proxy)
				return
			}
			proxy.ServeHTTP(w, r)
		})(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			if tok := r.URL.Query().Get("_token"); tok != "" {
				if !m.tokenMatches(tok) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if !m.isAllowedHostAndOrigin(r, false) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				m.mu.RLock()
				sec := m.uiSecret
				m.mu.RUnlock()
				http.SetCookie(w, &http.Cookie{
					Name:     uiSessionCookie,
					Value:    sec,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
		if !m.hasValidSession(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !m.isAllowedHostAndOrigin(r, false) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fileSrv.ServeHTTP(w, r)
	})
	return mux
}

func (m *CoreManager) startUIServer() error {
	targetURL, _ := url.Parse(m.daemonURL)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.FlushInterval = -1 // 实时刷新 SSE 事件流
	origDir := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDir(req)
		req.Header.Del("Cookie")
		req.Header.Del("X-GDPortal-UI-Token")
		m.mu.RLock()
		tok := m.daemonToken
		m.mu.RUnlock()
		req.Header.Set("X-GDPortal-Token", tok)
		req.Host = targetURL.Host
	}

	subUI, err := fs.Sub(uiAssetsFS, "ui")
	if err != nil {
		return err
	}
	fileSrv := http.FileServer(http.FS(subUI))
	handler := m.buildUIHandler(proxy, fileSrv)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	host := fmt.Sprintf("127.0.0.1:%d", port)
	origin := "http://" + host
	m.mu.Lock()
	m.uiHost = host
	m.uiOrigin = origin
	m.uiURL = origin + "/"
	m.uiServer = &http.Server{Handler: handler}
	m.mu.Unlock()

	go func() {
		_ = m.uiServer.Serve(ln)
	}()
	return nil
}

func (m *CoreManager) handleSettingsProxy(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var patch map[string]any
	if json.Unmarshal(body, &patch) == nil {
		m.mu.Lock()
		if v, ok := patch["closeToTray"].(bool); ok {
			m.closeToTray = v
		}
		if v, ok := patch["theme"].(string); ok {
			m.theme = v
		}
		m.mu.Unlock()
		if v, ok := patch["theme"].(string); ok && m.onThemeUI != nil {
			m.onThemeUI(v)
		}
		if v, ok := patch["autoStart"].(bool); ok {
			_ = setAutoStartEnabled(v)
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	proxy.ServeHTTP(w, r)
}

func (m *CoreManager) handleUIMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	exe, _ := os.Executable()
	m.mu.RLock()
	coreMode := m.coreMode
	theme := m.theme
	closeTray := m.closeToTray
	m.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"coreMode":    coreMode,
		"exePath":     exe,
		"autoStart":   isAutoStartEnabled(),
		"theme":       theme,
		"closeToTray": closeTray,
	})
}

func (m *CoreManager) handleUITheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Theme string `json:"theme"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Theme == "dark" || body.Theme == "light" || body.Theme == "system" {
		m.mu.Lock()
		m.theme = body.Theme
		m.mu.Unlock()
		if m.onThemeUI != nil {
			m.onThemeUI(body.Theme)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (m *CoreManager) handleUIAutoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	err := setAutoStartEnabled(body.Enabled)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "autoStart": isAutoStartEnabled()})
}

func (m *CoreManager) handleUISaveFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var savedPath string
	var err error
	if m.onOpenDialog != nil {
		savedPath, err = m.onOpenDialog(body.Name, body.Content)
	} else {
		home, _ := os.UserHomeDir()
		savedPath = filepath.Join(home, "Desktop", filepath.Base(body.Name))
		err = os.WriteFile(savedPath, []byte(body.Content), 0644)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": savedPath != "", "path": savedPath})
}

func (m *CoreManager) DaemonDo(method, path string, payload any) ([]byte, int, error) {
	m.mu.RLock()
	base := m.daemonURL
	tok := m.daemonToken
	m.mu.RUnlock()
	if base == "" {
		return nil, 0, errors.New("daemon not started")
	}
	var bodyReader io.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-GDPortal-Token", tok)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := &http.Client{Timeout: 8 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, nil
}

func (m *CoreManager) syncConfigFromDaemon() {
	raw, code, err := m.DaemonDo("GET", "/api/state", nil)
	if err != nil || code != 200 {
		return
	}
	var res struct {
		Config struct {
			Theme       string `json:"theme"`
			CloseToTray bool   `json:"closeToTray"`
			AutoConnect bool   `json:"autoConnect"`
			Account     string `json:"account"`
			HasSavedPwd bool   `json:"hasSavedPassword"`
			ForceReauth bool   `json:"forceReauth"`
			Manual      bool   `json:"manualOverride"`
			School      string `json:"school"`
			Domain      string `json:"domain"`
			Area        string `json:"area"`
			PinnedIfIdx uint32 `json:"pinnedIfIndex"`
			DebugWire   bool   `json:"debugWire"`
			QueryState  bool   `json:"queryState"`
			RememberPwd bool   `json:"rememberPassword"`
		} `json:"config"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return
	}
	m.mu.Lock()
	if res.Config.Theme != "" {
		m.theme = res.Config.Theme
	}
	m.closeToTray = res.Config.CloseToTray
	m.mu.Unlock()
	if m.onThemeUI != nil && res.Config.Theme != "" {
		m.onThemeUI(res.Config.Theme)
	}
	if res.Config.AutoConnect && res.Config.Account != "" && res.Config.HasSavedPwd {
		go func() {
			_, _, _ = m.DaemonDo("POST", "/api/connect", map[string]any{
				"account":          res.Config.Account,
				"useSavedPassword": true,
				"rememberPassword": res.Config.RememberPwd,
				"force":            res.Config.ForceReauth,
				"manualOverride":   res.Config.Manual,
				"school":           res.Config.School,
				"domain":           res.Config.Domain,
				"area":             res.Config.Area,
				"pinnedIfIndex":    res.Config.PinnedIfIdx,
				"debugWire":        res.Config.DebugWire,
				"queryState":       res.Config.QueryState,
			})
		}()
	}
}

func (m *CoreManager) TriggerSavedConnect(force bool) error {
	raw, code, err := m.DaemonDo("GET", "/api/state", nil)
	if err != nil || code != 200 {
		return errors.New("无法读取保存的配置")
	}
	var res struct {
		Config struct {
			Account     string `json:"account"`
			HasSavedPwd bool   `json:"hasSavedPassword"`
			RememberPwd bool   `json:"rememberPassword"`
			Manual      bool   `json:"manualOverride"`
			School      string `json:"school"`
			Domain      string `json:"domain"`
			Area        string `json:"area"`
			PinnedIfIdx uint32 `json:"pinnedIfIndex"`
			DebugWire   bool   `json:"debugWire"`
			QueryState  bool   `json:"queryState"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return err
	}
	if res.Config.Account == "" || !res.Config.HasSavedPwd {
		return errors.New("请先在主界面输入账号密码并连接一次")
	}
	_, _, err = m.DaemonDo("POST", "/api/connect", map[string]any{
		"account":          res.Config.Account,
		"useSavedPassword": true,
		"rememberPassword": res.Config.RememberPwd,
		"force":            force,
		"manualOverride":   res.Config.Manual,
		"school":           res.Config.School,
		"domain":           res.Config.Domain,
		"area":             res.Config.Area,
		"pinnedIfIndex":    res.Config.PinnedIfIdx,
		"debugWire":        res.Config.DebugWire,
		"queryState":       res.Config.QueryState,
	})
	return err
}

func (m *CoreManager) UIURL() string {
	m.mu.RLock()
	u := m.uiURL
	sec := m.uiSecret
	m.mu.RUnlock()
	if u == "" {
		return ""
	}
	return fmt.Sprintf("%s?_token=%s", u, sec)
}

func (m *CoreManager) CloseToTray() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closeToTray
}

func (m *CoreManager) Theme() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.theme
}

func (m *CoreManager) Shutdown() {
	_, _, _ = m.DaemonDo("POST", "/api/shutdown", nil)
	m.mu.Lock()
	stdin := m.stdinPipe
	cmd := m.cmd
	srv := m.uiServer
	m.stdinPipe = nil
	m.cmd = nil
	m.uiServer = nil
	m.mu.Unlock()

	if stdin != nil {
		_ = stdin.Close()
	}
	if cmd != nil && cmd.Process != nil {
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	if srv != nil {
		_ = srv.Close()
	}
}
