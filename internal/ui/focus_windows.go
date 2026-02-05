//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

var (
	user32                       = syscall.NewLazyDLL("user32.dll")
	procGetForegroundWindow      = user32.NewProc("GetForegroundWindow")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procAttachThreadInput        = user32.NewProc("AttachThreadInput")
	procGetCurrentThreadId       = user32.NewProc("GetCurrentThreadId")
	procBringWindowToTop         = user32.NewProc("BringWindowToTop")
	procShowWindow               = user32.NewProc("ShowWindow")
	procFindWindowW              = user32.NewProc("FindWindowW")
)

const (
	SW_SHOW    = 5
	SW_RESTORE = 9
)

func bringWindowToForeground(windowTitle string) {
	titlePtr, _ := syscall.UTF16PtrFromString(windowTitle)
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
	if hwnd == 0 {
		return
	}

	foregroundHwnd, _, _ := procGetForegroundWindow.Call()

	var foregroundThreadId uintptr
	if foregroundHwnd != 0 {
		foregroundThreadId, _, _ = procGetWindowThreadProcessId.Call(foregroundHwnd, 0)
	}

	currentThreadId, _, _ := procGetCurrentThreadId.Call()

	if foregroundThreadId != currentThreadId && foregroundThreadId != 0 {
		procAttachThreadInput.Call(currentThreadId, foregroundThreadId, 1)
		defer procAttachThreadInput.Call(currentThreadId, foregroundThreadId, 0)
	}

	procShowWindow.Call(hwnd, SW_RESTORE)
	procSetForegroundWindow.Call(hwnd)
	procBringWindowToTop.Call(hwnd)
}
