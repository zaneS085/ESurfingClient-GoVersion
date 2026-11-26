package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"github.com/wailsapp/go-webview2/webviewloader"
)

var (
	modKernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleW    = modKernel32.NewProc("GetModuleHandleW")
	procCreateMutexW        = modKernel32.NewProc("CreateMutexW")
	modOle32                = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx      = modOle32.NewProc("CoInitializeEx")
	procCoUninitialize      = modOle32.NewProc("CoUninitialize")
	modUser32               = syscall.NewLazyDLL("user32.dll")
	procRegisterClassExW    = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW     = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow       = modUser32.NewProc("DestroyWindow")
	procDefWindowProcW      = modUser32.NewProc("DefWindowProcW")
	procShowWindow          = modUser32.NewProc("ShowWindow")
	procUpdateWindow        = modUser32.NewProc("UpdateWindow")
	procIsIconic            = modUser32.NewProc("IsIconic")
	procFindWindowW         = modUser32.NewProc("FindWindowW")
	procPostMessageW        = modUser32.NewProc("PostMessageW")
	procPostQuitMessage     = modUser32.NewProc("PostQuitMessage")
	procGetMessageW         = modUser32.NewProc("GetMessageW")
	procTranslateMessage    = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW    = modUser32.NewProc("DispatchMessageW")
	procSystemParametersInf = modUser32.NewProc("SystemParametersInfoW")
	procGetDpiForSystem     = modUser32.NewProc("GetDpiForSystem")
	procGetDpiForWindow     = modUser32.NewProc("GetDpiForWindow")
	procSetProcessDpiCtx    = modUser32.NewProc("SetProcessDpiAwarenessContext")
	procSetWindowPos        = modUser32.NewProc("SetWindowPos")
	procLoadCursorW         = modUser32.NewProc("LoadCursorW")
	procMessageBoxW         = modUser32.NewProc("MessageBoxW")
	modDwmapi               = syscall.NewLazyDLL("dwmapi.dll")
	procDwmSetWindowAttr    = modDwmapi.NewProc("DwmSetWindowAttribute")
	modComdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetSaveFileNameW    = modComdlg32.NewProc("GetSaveFileNameW")
)

const (
	ownerClassName = "GDPortalHiddenOwnerClass"
	mainClassName  = "GDPortalMainWindowClass"
	singleMutex    = "Local\\GDPortalDesktopSingleInstance"

	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	swShow             = 5
	swRestore          = 9
	csHRedraw          = 0x0002
	csVRedraw          = 0x0001
	idcArrow           = 32512
	spiGetWorkArea     = 48
	wmDestroy          = 0x0002
	wmMove             = 0x0003
	wmSize             = 0x0005
	wmClose            = 0x0010
	wmGetMinMaxInfo    = 0x0024
	wmAppTheme         = 0x8000 + 1
	wmAppActivate      = 0x8000 + 2
	wmAppTooltip       = 0x8000 + 3
	wmAppQuit          = 0x8000 + 4

	swpNoMove      = 0x0002
	swpNoSize      = 0x0001
	swpNoZOrder    = 0x0004
	swpFrameChange = 0x0020

	dpiAwarePerMonitorV2 = ^uintptr(3) // (DPI_AWARENESS_CONTEXT)-4
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type rectW struct {
	left, top, right, bottom int32
}

type minMaxInfoW struct {
	reserved     pointW
	maxSize      pointW
	maxPosition  pointW
	minTrackSize pointW
	maxTrackSize pointW
}

type msgW struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      pointW
}

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

type desktopApp struct {
	core      *CoreManager
	hInst     uintptr
	hIcon     uintptr
	ownerHwnd uintptr
	mainHwnd  uintptr
	chrom     *edge.Chromium
	wvAvail   bool
	mu        sync.Mutex
	dark      bool
	tipText   string
	stopSSE   chan struct{}
}

var globalApp *desktopApp

func resolveDarkBool(theme string) bool {
	switch theme {
	case "light":
		return false
	case "system":
		return isWindowsDarkTheme()
	default:
		return true
	}
}

func applyDwmDark(hwnd uintptr, dark bool) {
	if hwnd == 0 || procDwmSetWindowAttr.Find() != nil {
		return
	}
	var val int32
	if dark {
		val = 1
	}
	r, _, _ := procDwmSetWindowAttr.Call(hwnd, 20, uintptr(unsafe.Pointer(&val)), 4)
	if r != 0 {
		procDwmSetWindowAttr.Call(hwnd, 19, uintptr(unsafe.Pointer(&val)), 4)
	}
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swpNoMove|swpNoSize|swpNoZOrder|swpFrameChange)
}

func (a *desktopApp) openMainWindow() {
	if !a.wvAvail {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", a.core.UIURL()).Start()
		showTrayBalloon(a.ownerHwnd, "GDPortal 已在浏览器打开", "当前系统未安装 Edge WebView2 Runtime，已回退到默认浏览器展示界面。")
		return
	}
	if a.mainHwnd != 0 {
		iconic, _, _ := procIsIconic.Call(a.mainHwnd)
		if iconic != 0 {
			procShowWindow.Call(a.mainHwnd, swRestore)
		} else {
			procShowWindow.Call(a.mainHwnd, swShow)
		}
		procSetForegroundWindow.Call(a.mainHwnd)
		return
	}

	dpi := uint32(96)
	if procGetDpiForSystem.Find() == nil {
		if d, _, _ := procGetDpiForSystem.Call(); d >= 96 {
			dpi = uint32(d)
		}
	}
	w := int32(940 * dpi / 96)
	h := int32(640 * dpi / 96)
	var wa rectW
	procSystemParametersInf.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&wa)), 0)
	x := wa.left + (wa.right-wa.left-w)/2
	y := wa.top + (wa.bottom-wa.top-h)/2
	if wa.right == 0 {
		x, y = 160, 100
	}

	clsPtr, _ := syscall.UTF16PtrFromString(mainClassName)
	titlePtr, _ := syscall.UTF16PtrFromString("GDPortal 校园网客户端")
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		wsOverlappedWindow,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		0, 0, a.hInst, 0,
	)
	if hwnd == 0 {
		return
	}
	a.mainHwnd = hwnd
	a.mu.Lock()
	dark := a.dark
	a.mu.Unlock()
	applyDwmDark(hwnd, dark)

	chrom := edge.NewChromium()
	chrom.DataPath = filepath.Join(localAppDataDir(), "WebView2")
	chrom.SetErrorCallback(func(err error) {
		_ = err
	})
	a.chrom = chrom
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)

	if ok := chrom.Embed(hwnd); !ok || chrom.GetController() == nil {
		// WebView2 启动失败则释放窗体并回退系统浏览器
		a.destroyMainWindow()
		a.wvAvail = false
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", a.core.UIURL()).Start()
		return
	}
	if dark {
		chrom.SetBackgroundColour(31, 31, 31, 255)
	} else {
		chrom.SetBackgroundColour(255, 255, 255, 255)
	}
	_ = chrom.PutIsSwipeNavigationEnabled(false)
	chrom.Resize()
	chrom.Navigate(a.core.UIURL())
}

func (a *desktopApp) destroyMainWindow() {
	if a.chrom != nil {
		a.chrom.ShuttingDown()
		if ctrl := a.chrom.GetController(); ctrl != nil {
			_ = ctrl.PutIsVisible(false)
			ctrl.Release()
		}
		a.chrom.Release()
		a.chrom = nil
	}
	if a.mainHwnd != 0 {
		h := a.mainHwnd
		a.mainHwnd = 0
		procDestroyWindow.Call(h)
	}
	runtime.GC()
}

func (a *desktopApp) quitAll() {
	select {
	case <-a.stopSSE:
	default:
		close(a.stopSSE)
	}
	a.destroyMainWindow()
	removeTrayIcon(a.ownerHwnd)
	a.core.Shutdown()
	if a.ownerHwnd != 0 {
		procDestroyWindow.Call(a.ownerHwnd)
		a.ownerHwnd = 0
	}
	if a.hIcon != 0 {
		procDestroyIcon.Call(a.hIcon)
		a.hIcon = 0
	}
	procPostQuitMessage.Call(0)
}

func saveFileWithDialog(defaultName, content string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = procCoInitializeEx.Find()
	hr, _, _ := procCoInitializeEx.Call(0, 0x2) // COINIT_APARTMENTTHREADED
	if hr == 0 || hr == 1 {
		defer procCoUninitialize.Call()
	}

	var buf [520]uint16
	u16Name := utf16.Encode([]rune(filepath.Base(defaultName)))
	if len(u16Name) >= len(buf) {
		u16Name = u16Name[:len(buf)-1]
	}
	copy(buf[:], u16Name)

	ext := strings.TrimPrefix(filepath.Ext(defaultName), ".")
	filter := "Markdown (*.md)\x00*.md\x00JSON (*.json)\x00*.json\x00All Files (*.*)\x00*.*\x00\x00"
	if ext == "json" {
		filter = "JSON (*.json)\x00*.json\x00Markdown (*.md)\x00*.md\x00All Files (*.*)\x00*.*\x00\x00"
	}
	filterU16 := utf16.Encode([]rune(filter))
	titleU16, _ := syscall.UTF16PtrFromString("导出 GDPortal 脱敏诊断报告")
	defExtU16, _ := syscall.UTF16PtrFromString(ext)

	home, _ := os.UserHomeDir()
	initDir := filepath.Join(home, "Desktop")
	initDirU16, _ := syscall.UTF16PtrFromString(initDir)

	var ofn openFileNameW
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.lpstrFilter = &filterU16[0]
	ofn.nFilterIndex = 1
	ofn.lpstrFile = &buf[0]
	ofn.nMaxFile = uint32(len(buf))
	ofn.lpstrInitialDir = initDirU16
	ofn.lpstrTitle = titleU16
	ofn.lpstrDefExt = defExtU16
	ofn.flags = 0x00000002 | 0x00000800 | 0x00000008 // OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR

	r, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "", nil
	}
	target := syscall.UTF16ToString(buf[:])
	if target == "" {
		return "", nil
	}
	if err := os.WriteFile(target, []byte(content), 0644); err != nil {
		return "", err
	}
	return target, nil
}

func ownerWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	a := globalApp
	switch msg {
	case wmTrayCb:
		ev := uint32(lParam)
		switch ev {
		case wmLButtonUp, wmLButtonDbl:
			a.openMainWindow()
		case wmRButtonUp, wmContextMenu:
			switch showTrayContextMenu(hwnd) {
			case idTrayOpen:
				a.openMainWindow()
			case idTrayReconnect:
				go func() {
					if err := a.core.TriggerSavedConnect(true); err != nil {
						procPostMessageW.Call(hwnd, wmAppActivate, 0, 0)
						showTrayBalloon(hwnd, "GDPortal", err.Error())
					}
				}()
			case idTrayDisconnect:
				go func() {
					_, _, _ = a.core.DaemonDo("POST", "/api/disconnect", nil)
				}()
			case idTrayQuit:
				a.quitAll()
			}
		}
		return 0
	case wmAppTheme:
		a.mu.Lock()
		dark := a.dark
		a.mu.Unlock()
		if a.mainHwnd != 0 {
			applyDwmDark(a.mainHwnd, dark)
			if a.chrom != nil {
				if dark {
					a.chrom.SetBackgroundColour(31, 31, 31, 255)
				} else {
					a.chrom.SetBackgroundColour(255, 255, 255, 255)
				}
			}
		}
		return 0
	case wmAppActivate:
		a.openMainWindow()
		return 0
	case wmAppTooltip:
		a.mu.Lock()
		tip := a.tipText
		a.mu.Unlock()
		updateTrayTip(hwnd, tip)
		return 0
	case wmAppQuit:
		a.quitAll()
		return 0
	case wmDestroy:
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func mainWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	a := globalApp
	switch msg {
	case wmSize:
		if a != nil && a.chrom != nil {
			a.chrom.Resize()
		}
		return 0
	case wmMove:
		if a != nil && a.chrom != nil {
			_ = a.chrom.NotifyParentWindowPositionChanged()
		}
		return 0
	case wmGetMinMaxInfo:
		mmi := (*minMaxInfoW)(unsafe.Pointer(lParam))
		dpi := uint32(96)
		if procGetDpiForWindow.Find() == nil && hwnd != 0 {
			if d, _, _ := procGetDpiForWindow.Call(hwnd); d >= 96 {
				dpi = uint32(d)
			}
		}
		mmi.minTrackSize.x = int32(760 * dpi / 96)
		mmi.minTrackSize.y = int32(520 * dpi / 96)
		return 0
	case wmClose:
		if a != nil {
			if a.core.CloseToTray() {
				a.destroyMainWindow()
			} else {
				a.quitAll()
			}
		}
		return 0
	case wmDestroy:
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func registerWndClass(clsName string, proc uintptr, hInst, hIcon uintptr) error {
	clsPtr, _ := syscall.UTF16PtrFromString(clsName)
	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	var wc wndClassExW
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	wc.style = csHRedraw | csVRedraw
	wc.lpfnWndProc = proc
	wc.hInstance = hInst
	wc.hIcon = hIcon
	wc.hIconSm = hIcon
	wc.hCursor = cursor
	wc.hbrBackground = 0
	wc.lpszClassName = clsPtr
	r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if r == 0 {
		return fmt.Errorf("RegisterClassExW(%s): %v", clsName, err)
	}
	return nil
}

func (a *desktopApp) watchStateForTray() {
	for {
		select {
		case <-a.stopSSE:
			return
		default:
		}
		req, err := http.NewRequest("GET", a.core.daemonURL+"/api/events", nil)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		a.core.mu.RLock()
		tok := a.core.daemonToken
		a.core.mu.RUnlock()
		req.Header.Set("X-GDPortal-Token", tok)

		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			select {
			case <-a.stopSSE:
				resp.Body.Close()
				return
			default:
			}
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var pkt struct {
				Type string `json:"type"`
				Data struct {
					State  string `json:"state"`
					School string `json:"school"`
					Domain string `json:"domain"`
					UserIP string `json:"userIP"`
				} `json:"data"`
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &pkt) == nil && pkt.Type == "state" {
				tip := "GDPortal · 未连接"
				switch pkt.Data.State {
				case "connected":
					meta := strings.TrimSpace(pkt.Data.School + " " + pkt.Data.Domain)
					if meta == "" {
						meta = pkt.Data.UserIP
					}
					if meta != "" {
						tip = "GDPortal · 已连接 (" + meta + ")"
					} else {
						tip = "GDPortal · 已连接"
					}
				case "connecting":
					tip = "GDPortal · 正在连接..."
				case "disconnecting":
					tip = "GDPortal · 正在注销..."
				case "error":
					tip = "GDPortal · 认证异常 (点击查看)"
				}
				a.mu.Lock()
				changed := a.tipText != tip
				a.tipText = tip
				a.mu.Unlock()
				if changed && a.ownerHwnd != 0 {
					procPostMessageW.Call(a.ownerHwnd, wmAppTooltip, 0, 0)
				}
			}
		}
		resp.Body.Close()
		time.Sleep(1500 * time.Millisecond)
	}
}

func showErrorMsgBox(title, msg string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}

func main() {
	minimized := flag.Bool("minimized", false, "启动后仅驻留系统托盘 (低内存模式)")
	coreOverride := flag.String("core", "", "开发模式: 指定外部 gdportal-lite.exe 路径")
	flag.Parse()

	// 单实例检测: 若已在运行则激活已有窗口并退出
	mtxName, _ := syscall.UTF16PtrFromString(singleMutex)
	hMtx, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(mtxName)))
	if hMtx != 0 && err == syscall.Errno(183) { // ERROR_ALREADY_EXISTS
		clsPtr, _ := syscall.UTF16PtrFromString(ownerClassName)
		existing, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(clsPtr)), 0)
		if existing != 0 {
			procPostMessageW.Call(existing, wmAppActivate, 0, 0)
		}
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if procSetProcessDpiCtx.Find() == nil {
		procSetProcessDpiCtx.Call(dpiAwarePerMonitorV2)
	}
	_, _, _ = procCoInitializeEx.Call(0, 0x2) // COINIT_APARTMENTTHREADED
	defer procCoUninitialize.Call()

	app := &desktopApp{
		dark:    true,
		tipText: "GDPortal · 未连接",
		stopSSE: make(chan struct{}),
	}
	globalApp = app

	core := NewCoreManager(
		*coreOverride,
		func(theme string) {
			app.mu.Lock()
			app.dark = resolveDarkBool(theme)
			app.mu.Unlock()
			if app.ownerHwnd != 0 {
				procPostMessageW.Call(app.ownerHwnd, wmAppTheme, 0, 0)
			}
		},
		saveFileWithDialog,
	)
	app.core = core

	if err := core.Start(); err != nil {
		showErrorMsgBox("GDPortal 启动失败", err.Error())
		return
	}

	ver, wvErr := webviewloader.GetAvailableCoreWebView2BrowserVersionString("")
	app.wvAvail = wvErr == nil && ver != ""

	hInst, _, _ := procGetModuleHandleW.Call(0)
	app.hInst = hInst
	app.hIcon = createAppHICON()

	if err := registerWndClass(ownerClassName, syscall.NewCallback(ownerWndProc), hInst, app.hIcon); err != nil {
		core.Shutdown()
		showErrorMsgBox("GDPortal 窗口初始化失败", err.Error())
		return
	}
	if err := registerWndClass(mainClassName, syscall.NewCallback(mainWndProc), hInst, app.hIcon); err != nil {
		core.Shutdown()
		showErrorMsgBox("GDPortal 窗口初始化失败", err.Error())
		return
	}

	ownerClsPtr, _ := syscall.UTF16PtrFromString(ownerClassName)
	ownerTitlePtr, _ := syscall.UTF16PtrFromString("GDPortalTrayOwner")
	ownerHwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(ownerClsPtr)),
		uintptr(unsafe.Pointer(ownerTitlePtr)),
		0, // invisible top-level owner (for tray & FindWindowW)
		0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if ownerHwnd == 0 {
		core.Shutdown()
		return
	}
	app.ownerHwnd = ownerHwnd
	addTrayIcon(ownerHwnd, app.hIcon, app.tipText)

	go app.watchStateForTray()

	app.mu.Lock()
	app.dark = resolveDarkBool(core.Theme())
	app.mu.Unlock()

	if !*minimized {
		app.openMainWindow()
	}

	var m msgW
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	core.Shutdown()
}
