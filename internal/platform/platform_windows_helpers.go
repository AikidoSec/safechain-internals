//go:build windows

package platform

import (
	"context"
	"fmt"
	"log"
	"strings"
	"unsafe"

	"github.com/AikidoSec/safechain-internals/internal/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const PROCESS_TIMEOUT_MS = 60000 // 1 minute

func getCurrentUserToken() (*windows.Token, error) {
	var sessionInfo *windows.WTS_SESSION_INFO
	var count uint32

	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessionInfo, &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions failed: %v", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionInfo)))

	sessions := unsafe.Slice(sessionInfo, count)
	for _, session := range sessions {
		// get the current active session that's not root
		if session.State == windows.WTSActive && session.SessionID != 0 {
			var token windows.Token
			if err := windows.WTSQueryUserToken(session.SessionID, &token); err == nil {
				return &token, nil
			}
		}
	}

	return nil, fmt.Errorf("no active user session found")
}

func getLoggedInUserSIDs(ctx context.Context) ([]string, error) {
	output, err := utils.RunCommand(ctx, "reg", "query", "HKU")
	if err != nil {
		return nil, fmt.Errorf("failed to query HKU: %v", err)
	}

	var sids []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HKEY_USERS\\") {
			continue
		}
		sid := strings.TrimPrefix(line, "HKEY_USERS\\")

		// local system accounts -> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue
		}
		if strings.HasSuffix(sid, "_Classes") {
			continue
		}
		sids = append(sids, sid)
	}
	return sids, nil
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

func runProcessAsUser(duplicatedToken windows.Token, cmdLinePtr *uint16, envBlock *uint16) (string, error) {
	var stdoutRead, stdoutWrite windows.Handle
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})), // The size, in bytes, of this structure -> https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
		InheritHandle:      1,
		SecurityDescriptor: nil,
	}
	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return "", fmt.Errorf("CreatePipe failed: %v", err)
	}
	defer windows.CloseHandle(stdoutRead)
	defer func() {
		if stdoutWrite != 0 {
			windows.CloseHandle(stdoutWrite)
		}
	}()

	if err := windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return "", fmt.Errorf("SetHandleInformation failed: %v", err)
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop, _ = windows.UTF16PtrFromString("winsta0\\default")
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdOutput = stdoutWrite
	si.StdErr = stdoutWrite

	var pi windows.ProcessInformation

	if err := windows.CreateProcessAsUser(duplicatedToken, nil, cmdLinePtr, nil, nil, true, windows.CREATE_UNICODE_ENVIRONMENT, envBlock, nil, &si, &pi); err != nil {
		return "", fmt.Errorf("CreateProcessAsUser failed: %v", err)
	}

	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	event, err := windows.WaitForSingleObject(pi.Process, PROCESS_TIMEOUT_MS)
	if err != nil {
		return "", fmt.Errorf("WaitForSingleObject failed: %v", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		return "", fmt.Errorf("process timed out after 1 minute")
	}
	if event != windows.WAIT_OBJECT_0 {
		return "", fmt.Errorf("unexpected wait result: %d", event)
	}

	// Need to close this earlier so the pipe is fully closed and flushed before reading the output
	windows.CloseHandle(stdoutWrite)
	stdoutWrite = 0

	var output []byte
	buf := make([]byte, 4096)
	for {
		var bytesRead uint32
		err := windows.ReadFile(stdoutRead, buf, &bytesRead, nil)
		if err != nil || bytesRead == 0 {
			break
		}
		output = append(output, buf[:bytesRead]...)
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(pi.Process, &exitCode); err != nil {
		return "", fmt.Errorf("GetExitCodeProcess failed: %v", err)
	}
	if exitCode != 0 {
		err := fmt.Errorf("process exited with code %d", exitCode)
		log.Printf("\t- Command error: %v", err)
		log.Printf("\t- Command output: %s", string(output))
		return "", err
	}

	return string(output), nil
}

func runAsLoggedInUser(binaryPath string, args []string) (string, error) {
	userToken, err := getCurrentUserToken()
	if err != nil {
		return "", fmt.Errorf("getCurrentUserToken failed: %v", err)
	}
	defer userToken.Close()

	var duplicatedToken windows.Token
	if err := windows.DuplicateTokenEx(*userToken, 0, nil, windows.SecurityImpersonation, windows.TokenPrimary, &duplicatedToken); err != nil {
		return "", fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	defer duplicatedToken.Close()

	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, duplicatedToken, false); err != nil {
		return "", fmt.Errorf("CreateEnvironmentBlock failed: %v", err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	cmdLinePtr := buildCommandLineForWindowsProcess(binaryPath, args)
	if cmdLinePtr == nil {
		return "", fmt.Errorf("failed to get command line for process")
	}

	output, err := runProcessAsUser(duplicatedToken, cmdLinePtr, envBlock)
	if err != nil {
		return "", fmt.Errorf("runProcessAsUser failed: %v", err)
	}

	return output, nil
}

type RegistryValue struct {
	Type  string
	Value string
	Data  string
}

func setRegistryValue(ctx context.Context, path string, value RegistryValue) error {
	// reg add with /f flag will overwrite the existing value if it exists
	_, err := utils.RunCommand(ctx, "reg", "add", path, "/v", value.Value, "/t", value.Type, "/d", value.Data, "/f")
	return err
}

func registryValueContains(ctx context.Context, path string, value string, toContain string) bool {
	output, err := utils.RunCommand(ctx, "reg", "query", path, "/v", value)
	if err != nil {
		return false
	}
	return strings.Contains(string(output), toContain)
}

func deleteRegistryValue(ctx context.Context, path string, value string) error {
	_, err := utils.RunCommand(ctx, "reg", "delete", path, "/v", value, "/f")
	return err
}

func readRegistryValue(key registry.Key, path string, valueName string) (string, error) {
	k, err := registry.OpenKey(key, path, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	val, _, err := k.GetStringValue(valueName)
	if err != nil {
		return "", fmt.Errorf("failed to read registry value %q: %w", valueName, err)
	}
	return val, nil
}
