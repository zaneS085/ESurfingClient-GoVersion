package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const runRegSubkey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runRegValue = "GDPortal"

func isAutoStartEnabled() bool {
	var hKey syscall.Handle
	sub, err := syscall.UTF16PtrFromString(runRegSubkey)
	if err != nil || syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, sub, 0, syscall.KEY_READ, &hKey) != nil {
		return false
	}
	defer syscall.RegCloseKey(hKey)
	valName, _ := syscall.UTF16PtrFromString(runRegValue)
	var typ uint32
	var buf [520]uint16
	n := uint32(len(buf) * 2)
	if syscall.RegQueryValueEx(hKey, valName, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) != nil {
		return false
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf[:n/2])) != ""
}

func setAutoStartEnabled(enabled bool) error {
	var hKey syscall.Handle
	sub, err := syscall.UTF16PtrFromString(runRegSubkey)
	if err != nil {
		return err
	}
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, sub, 0, syscall.KEY_SET_VALUE|syscall.KEY_QUERY_VALUE, &hKey); err != nil {
		return err
	}
	defer syscall.RegCloseKey(hKey)
	valName, _ := syscall.UTF16PtrFromString(runRegValue)

	if !enabled {
		modAdvapi := syscall.NewLazyDLL("advapi32.dll")
		procDel := modAdvapi.NewProc("RegDeleteValueW")
		r, _, _ := procDel.Call(uintptr(hKey), uintptr(unsafe.Pointer(valName)))
		if r != 0 && r != 2 { // ERROR_FILE_NOT_FOUND == 2
			return syscall.Errno(r)
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmdLine := `"` + exe + `" --minimized`
	u16, err := syscall.UTF16FromString(cmdLine)
	if err != nil {
		return err
	}
	modAdvapi := syscall.NewLazyDLL("advapi32.dll")
	procSet := modAdvapi.NewProc("RegSetValueExW")
	r, _, _ := procSet.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valName)),
		0,
		syscall.REG_SZ,
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(len(u16)*2),
	)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// isWindowsDarkTheme 读取 HKCU Personalize\AppsUseLightTheme 判断系统当前是否为深色模式
func isWindowsDarkTheme() bool {
	var hKey syscall.Handle
	sub, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`)
	if err != nil || syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, sub, 0, syscall.KEY_READ, &hKey) != nil {
		return true
	}
	defer syscall.RegCloseKey(hKey)
	valName, _ := syscall.UTF16PtrFromString("AppsUseLightTheme")
	var typ, val uint32
	n := uint32(4)
	if syscall.RegQueryValueEx(hKey, valName, nil, &typ, (*byte)(unsafe.Pointer(&val)), &n) != nil {
		return true
	}
	return val == 0
}
