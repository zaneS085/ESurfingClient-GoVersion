//go:build !(windows && 386)

package main

import (
	"errors"
	"gdportal-lite/x86emu"
	"io"
)

func preferNativeDLLEngine() bool { return false }

func newNativeDLLCipher([]byte, string) (Cipher, error) {
	return nil, errors.New("当前平台未启用原生 32 位 DLL 引擎")
}

func dllRun(img []byte, keyhex, mode string, input []byte) (string, error) {
	return x86emu.RunOnce(img, keyhex, mode, input)
}

func runDllWorker(io.Reader, io.Writer) error {
	return errors.New("-dllworker 仅用于 legacy windows/386 原生进程模式")
}
