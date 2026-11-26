package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestBuildAppICOAndHICON(t *testing.T) {
	ico := buildAppICO()
	if len(ico) < 22+40+32*32*4+128 {
		t.Fatalf("ico too short: %d", len(ico))
	}
	// ICONDIR: reserved=0, type=1, count=1
	if binary.LittleEndian.Uint16(ico[0:2]) != 0 ||
		binary.LittleEndian.Uint16(ico[2:4]) != 1 ||
		binary.LittleEndian.Uint16(ico[4:6]) != 1 {
		t.Fatalf("invalid ICONDIR header: %x", ico[:6])
	}
	if ico[6] != 32 || ico[7] != 32 {
		t.Fatalf("unexpected icon dims: %dx%d", ico[6], ico[7])
	}
	h := createAppHICON()
	if h == 0 {
		t.Fatal("createAppHICON returned 0")
	}
	_, _, _ = procDestroyIcon.Call(h)
}

func TestEmbeddedUIAssetsAndShellHandlers(t *testing.T) {
	for _, name := range []string{"ui/index.html", "ui/styles.css", "ui/app.js"} {
		b, err := fs.ReadFile(uiAssetsFS, name)
		if err != nil || len(b) == 0 {
			t.Fatalf("missing embedded asset %s: err=%v len=%d", name, err, len(b))
		}
	}

	var gotTheme string
	cm := NewCoreManager("", func(th string) { gotTheme = th }, nil)

	req := httptest.NewRequest("POST", "/api/ui/theme", strings.NewReader(`{"theme":"light"}`))
	rr := httptest.NewRecorder()
	cm.handleUITheme(rr, req)
	if rr.Code != http.StatusOK || gotTheme != "light" || cm.Theme() != "light" {
		t.Fatalf("handleUITheme: code=%d gotTheme=%q cmTheme=%q", rr.Code, gotTheme, cm.Theme())
	}

	reqMeta := httptest.NewRequest("GET", "/api/ui/meta", nil)
	rrMeta := httptest.NewRecorder()
	cm.handleUIMeta(rrMeta, reqMeta)
	if rrMeta.Code != http.StatusOK {
		t.Fatalf("handleUIMeta code=%d", rrMeta.Code)
	}
	var meta map[string]any
	if err := json.Unmarshal(rrMeta.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if meta["theme"] != "light" {
		t.Fatalf("meta theme = %v, want light", meta["theme"])
	}
}

func TestExtractEmbeddedCoreToTemp(t *testing.T) {
	if len(embeddedCoreGZ) < 100000 {
		t.Fatalf("embeddedCoreGZ looks truncated: %d bytes", len(embeddedCoreGZ))
	}
	origLocal := os.Getenv("LOCALAPPDATA")
	tmpDir := t.TempDir()
	t.Setenv("LOCALAPPDATA", tmpDir)
	defer os.Setenv("LOCALAPPDATA", origLocal)

	path, err := extractEmbeddedCore()
	if err != nil {
		t.Fatalf("extractEmbeddedCore: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read extracted core: %v", err)
	}
	if len(raw) < 1<<20 || !bytes.HasPrefix(raw, []byte("MZ")) {
		t.Fatalf("extracted core invalid MZ/size: len=%d", len(raw))
	}
	peOff := int(binary.LittleEndian.Uint32(raw[0x3C:0x40]))
	if peOff <= 0 || peOff+6 > len(raw) {
		t.Fatalf("invalid PE offset: %d", peOff)
	}
	if mach := binary.LittleEndian.Uint16(raw[peOff+4 : peOff+6]); mach != 0x8664 {
		t.Fatalf("extracted core PE Machine = 0x%04x, want 0x8664 (amd64)", mach)
	}
	// 第二次调用应命中缓存直接返回相同路径
	path2, err := extractEmbeddedCore()
	if err != nil || path2 != path {
		t.Fatalf("second extractEmbeddedCore = (%q, %v), want %q", path2, err, path)
	}
}

func TestUIServerAuthAndOriginProtection(t *testing.T) {
	var seenDaemonTok, seenCookie, seenUITok, seenMethod, seenPath string
	daemonMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenDaemonTok = r.Header.Get("X-GDPortal-Token")
		seenCookie = r.Header.Get("Cookie")
		seenUITok = r.Header.Get("X-GDPortal-UI-Token")
		seenMethod = r.Method
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer daemonMock.Close()

	cm := NewCoreManager("", nil, nil)
	cm.daemonURL = daemonMock.URL
	cm.daemonToken = "daemon-secret-xyz"

	targetURL, _ := url.Parse(cm.daemonURL)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	origDir := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDir(req)
		req.Header.Del("Cookie")
		req.Header.Del("X-GDPortal-UI-Token")
		cm.mu.RLock()
		tok := cm.daemonToken
		cm.mu.RUnlock()
		req.Header.Set("X-GDPortal-Token", tok)
		req.Host = targetURL.Host
	}
	subUI, err := fs.Sub(uiAssetsFS, "ui")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	fileSrv := http.FileServer(http.FS(subUI))

	uiSrv := httptest.NewServer(cm.buildUIHandler(proxy, fileSrv))
	defer uiSrv.Close()
	parsedUI, _ := url.Parse(uiSrv.URL)
	cm.mu.Lock()
	cm.uiHost = parsedUI.Host
	cm.uiOrigin = uiSrv.URL
	cm.uiURL = uiSrv.URL + "/"
	cm.mu.Unlock()

	noRedirectCl := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// 1. 未鉴权请求必须被拒绝 (401)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/api/ui/meta"},
		{http.MethodGet, "/api/state"},
		{http.MethodPost, "/api/ui/theme"},
	} {
		req, _ := http.NewRequest(tc.method, uiSrv.URL+tc.path, nil)
		resp, err := noRedirectCl.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s %s = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}

	// 2. 错误引导 _token 返回 401
	respBadBoot, err := noRedirectCl.Get(uiSrv.URL + "/?_token=wrong-token")
	if err != nil {
		t.Fatalf("bad boot get: %v", err)
	}
	respBadBoot.Body.Close()
	if respBadBoot.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad _token = %d, want 401", respBadBoot.StatusCode)
	}

	// 3. 正确 UIURL() 引导返回 302 + HttpOnly; SameSite=Strict Cookie
	respBoot, err := noRedirectCl.Get(cm.UIURL())
	if err != nil {
		t.Fatalf("valid boot get: %v", err)
	}
	respBoot.Body.Close()
	if respBoot.StatusCode != http.StatusFound || respBoot.Header.Get("Location") != "/" {
		t.Fatalf("boot redirect = (%d, %q), want (302, /)", respBoot.StatusCode, respBoot.Header.Get("Location"))
	}
	var sessionCookie *http.Cookie
	for _, ck := range respBoot.Cookies() {
		if ck.Name == uiSessionCookie {
			sessionCookie = ck
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("missing/weak session cookie: %+v", sessionCookie)
	}

	// 4. 校验错误 HTTP Method (405) 与代理阻断 /api/shutdown (403)
	req405, _ := http.NewRequest(http.MethodPost, uiSrv.URL+"/api/ui/meta", nil)
	req405.AddCookie(sessionCookie)
	resp405, err := noRedirectCl.Do(req405)
	if err != nil {
		t.Fatalf("405 req: %v", err)
	}
	resp405.Body.Close()
	if resp405.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/ui/meta = %d, want 405", resp405.StatusCode)
	}

	reqShut, _ := http.NewRequest(http.MethodPost, uiSrv.URL+"/api/shutdown", nil)
	reqShut.AddCookie(sessionCookie)
	respShut, err := noRedirectCl.Do(reqShut)
	if err != nil {
		t.Fatalf("shutdown proxy req: %v", err)
	}
	respShut.Body.Close()
	if respShut.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /api/shutdown via UI proxy = %d, want 403", respShut.StatusCode)
	}

	// 5. 带会话 Cookie 请求 /api/state 应注入 daemon token 并剥离桌面 Cookie/UIToken
	reqState, _ := http.NewRequest(http.MethodGet, uiSrv.URL+"/api/state", nil)
	reqState.AddCookie(sessionCookie)
	reqState.Header.Set("X-GDPortal-UI-Token", cm.uiSecret)
	respState, err := noRedirectCl.Do(reqState)
	if err != nil {
		t.Fatalf("GET /api/state: %v", err)
	}
	respState.Body.Close()
	if respState.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/state = %d, want 200", respState.StatusCode)
	}
	if seenDaemonTok != "daemon-secret-xyz" || seenCookie != "" || seenUITok != "" || seenMethod != http.MethodGet || seenPath != "/api/state" {
		t.Fatalf("proxy forwarded unexpected headers/req: daemonTok=%q cookie=%q uiTok=%q method=%q path=%q",
			seenDaemonTok, seenCookie, seenUITok, seenMethod, seenPath)
	}

	// 6. 跨源 Origin / 错误 Host / cross-site Sec-Fetch-Site 必须被拦截 (403)
	reqEvilOrigin, _ := http.NewRequest(http.MethodPost, uiSrv.URL+"/api/settings", strings.NewReader(`{"theme":"dark"}`))
	reqEvilOrigin.AddCookie(sessionCookie)
	reqEvilOrigin.Header.Set("Origin", "https://evil.example")
	respEvilOrigin, err := noRedirectCl.Do(reqEvilOrigin)
	if err != nil {
		t.Fatalf("evil origin req: %v", err)
	}
	respEvilOrigin.Body.Close()
	if respEvilOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST /api/settings = %d, want 403", respEvilOrigin.StatusCode)
	}

	reqEvilSFS, _ := http.NewRequest(http.MethodPost, uiSrv.URL+"/api/settings", strings.NewReader(`{"theme":"dark"}`))
	reqEvilSFS.AddCookie(sessionCookie)
	reqEvilSFS.Header.Set("Origin", uiSrv.URL)
	reqEvilSFS.Header.Set("Sec-Fetch-Site", "cross-site")
	respEvilSFS, err := noRedirectCl.Do(reqEvilSFS)
	if err != nil {
		t.Fatalf("evil sec-fetch-site req: %v", err)
	}
	respEvilSFS.Body.Close()
	if respEvilSFS.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site Sec-Fetch-Site POST = %d, want 403", respEvilSFS.StatusCode)
	}

	reqEvilHost, _ := http.NewRequest(http.MethodGet, uiSrv.URL+"/api/ui/meta", nil)
	reqEvilHost.AddCookie(sessionCookie)
	reqEvilHost.Host = "evil.example:80"
	respEvilHost, err := noRedirectCl.Do(reqEvilHost)
	if err != nil {
		t.Fatalf("evil host req: %v", err)
	}
	respEvilHost.Body.Close()
	if respEvilHost.StatusCode != http.StatusForbidden {
		t.Fatalf("evil Host GET = %d, want 403", respEvilHost.StatusCode)
	}

	// 7. 合法同源写请求应成功透传 (200)
	reqGoodWrite, _ := http.NewRequest(http.MethodPost, uiSrv.URL+"/api/settings", strings.NewReader(`{"theme":"light"}`))
	reqGoodWrite.AddCookie(sessionCookie)
	reqGoodWrite.Header.Set("Origin", uiSrv.URL)
	reqGoodWrite.Header.Set("Sec-Fetch-Site", "same-origin")
	reqGoodWrite.Header.Set("Referer", uiSrv.URL+"/")
	respGoodWrite, err := noRedirectCl.Do(reqGoodWrite)
	if err != nil {
		t.Fatalf("good write req: %v", err)
	}
	respGoodWrite.Body.Close()
	if respGoodWrite.StatusCode != http.StatusOK || seenPath != "/api/settings" || cm.Theme() != "light" {
		t.Fatalf("good same-origin write = (%d, %q, theme=%q), want (200, /api/settings, light)",
			respGoodWrite.StatusCode, seenPath, cm.Theme())
	}
}
