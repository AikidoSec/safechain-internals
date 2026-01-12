//go:build windows

package platform

import (
	"fmt"
	"log"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getActiveUserSessionID() (uint32, error) {
	var sessionInfo *windows.WTS_SESSION_INFO
	var count uint32

	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessionInfo, &count); err != nil {
		return 0, fmt.Errorf("WTSEnumerateSessions failed: %v", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionInfo)))

	sessions := unsafe.Slice(sessionInfo, count)
	for _, session := range sessions {
        // get the current active session that's not root
		if session.State == windows.WTSActive && session.SessionID != 0 {
			var token windows.Token
			if err := windows.WTSQueryUserToken(session.SessionID, &token); err == nil {
				token.Close()
				return session.SessionID, nil
			}
		}
	}

	return 0, fmt.Errorf("no active user session found")
}

func buildCommandLineForWindowsProcess(binaryPath string, args []string) *uint16 {
	cmdLine := binaryPath
	if len(args) > 0 {
		cmdLine = fmt.Sprintf(`"%s" %s`, binaryPath, strings.Join(args, " "))
	} else {
		cmdLine = fmt.Sprintf(`"%s"`, binaryPath)
	}
	cmdLinePtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil
	}
	return cmdLinePtr
}

func runProcessAsUser(duplicatedToken windows.Token, cmdLinePtr *uint16, envBlock *uint16) error {
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop, _ = windows.UTF16PtrFromString("winsta0\\default")

	var pi windows.ProcessInformation

	if err := windows.CreateProcessAsUser(duplicatedToken, nil, cmdLinePtr, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, envBlock, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser failed: %v", err)
	}

	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	event, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject failed: %v", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected wait result: %d", event)
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(pi.Process, &exitCode); err != nil {
		return fmt.Errorf("GetExitCodeProcess failed: %v", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("process exited with code %d", exitCode)
	}

	return nil
}

func runAsLoggedInUser(binaryPath string, args []string) error {
	sessionID, err := getActiveUserSessionID()
	if err != nil {
		return err
	}

	log.Printf("Found active user session: %d", sessionID)

	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return fmt.Errorf("WTSQueryUserToken failed: %v", err)
	}
	defer userToken.Close()

	var duplicatedToken windows.Token
	if err := windows.DuplicateTokenEx(userToken, 0, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicatedToken); err != nil {
		return fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	defer duplicatedToken.Close()

	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, duplicatedToken, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock failed: %v", err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	cmdLinePtr := buildCommandLineForWindowsProcess(binaryPath, args)
	if cmdLinePtr == nil {
		return fmt.Errorf("failed to get command line for process")
	}

	if err := runProcessAsUser(duplicatedToken, cmdLinePtr, envBlock); err != nil {
		return fmt.Errorf("runProcessAsUser failed: %v", err)
	}

	log.Printf("Process %s completed successfully as logged-in user", binaryPath)
	return nil
}
