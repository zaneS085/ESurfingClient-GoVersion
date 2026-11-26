package main

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	modShell32              = syscall.NewLazyDLL("shell32.dll")
	procShellNotifyIconW    = modShell32.NewProc("Shell_NotifyIconW")
	procCreatePopupMenu     = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = modUser32.NewProc("AppendMenuW")
	procDestroyMenu         = modUser32.NewProc("DestroyMenu")
	procTrackPopupMenu      = modUser32.NewProc("TrackPopupMenu")
	procGetCursorPos        = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
)

const (
	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nifMessage    = 0x00000001
	nifIcon       = 0x00000002
	nifTip        = 0x00000004
	nifInfo       = 0x00000010
	niifInfo      = 0x00000001
	wmTrayCb      = 0x8000 + 10 // WM_APP + 10
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	tpmLeftAlign  = 0x0000
	tpmBottomAlign = 0x0020
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100

	idTrayOpen       = 1001
	idTrayReconnect  = 1002
	idTrayDisconnect = 1003
	idTrayQuit       = 1004
)

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type pointW struct {
	x, y int32
}

func copyUTF16Fixed(dst []uint16, s string) {
	for i := range dst {
		dst[i] = 0
	}
	enc := utf16.Encode([]rune(s))
	n := len(enc)
	if n >= len(dst) {
		n = len(dst) - 1
	}
	copy(dst[:n], enc[:n])
}

func addTrayIcon(hwnd, hicon uintptr, tip string) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = wmTrayCb
	nid.hIcon = hicon
	copyUTF16Fixed(nid.szTip[:], tip)
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
}

func updateTrayTip(hwnd uintptr, tip string) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifTip
	copyUTF16Fixed(nid.szTip[:], tip)
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func showTrayBalloon(hwnd uintptr, title, msg string) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifInfo
	nid.dwInfoFlags = niifInfo
	copyUTF16Fixed(nid.szInfoTitle[:], title)
	copyUTF16Fixed(nid.szInfo[:], msg)
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func removeTrayIcon(hwnd uintptr) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func showTrayContextMenu(ownerHwnd uintptr) uint32 {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return 0
	}
	defer procDestroyMenu.Call(hMenu)

	appendItem := func(flags uintptr, id uintptr, text string) {
		var p uintptr
		if text != "" {
			u16, _ := syscall.UTF16PtrFromString(text)
			p = uintptr(unsafe.Pointer(u16))
		}
		procAppendMenuW.Call(hMenu, flags, id, p)
	}

	appendItem(mfString, idTrayOpen, "打开主界面")
	appendItem(mfString, idTrayReconnect, "连接 / 强制重连")
	appendItem(mfString, idTrayDisconnect, "断开并下线")
	appendItem(mfSeparator, 0, "")
	appendItem(mfString, idTrayQuit, "退出并下线")

	var pt pointW
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(ownerHwnd)
	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmLeftAlign|tpmBottomAlign|tpmRightButton|tpmReturnCmd,
		uintptr(pt.x),
		uintptr(pt.y),
		0,
		ownerHwnd,
		0,
	)
	return uint32(cmd)
}
