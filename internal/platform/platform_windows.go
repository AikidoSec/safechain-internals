//go:build windows

package platform

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/AikidoSec/safechain-agent/internal/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var (
	modwtsapi32                  = windows.NewLazySystemDLL("wtsapi32.dll")
	modadvapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	moduserenv                   = windows.NewLazySystemDLL("userenv.dll")
	procWTSEnumerateSessions     = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory            = modwtsapi32.NewProc("WTSFreeMemory")
	procWTSQueryUserToken        = modwtsapi32.NewProc("WTSQueryUserToken")
	procDuplicateTokenEx         = modadvapi32.NewProc("DuplicateTokenEx")
	procCreateProcessAsUserW     = modadvapi32.NewProc("CreateProcessAsUserW")
	procCreateEnvironmentBlock   = moduserenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock  = moduserenv.NewProc("DestroyEnvironmentBlock")
	procGetUserProfileDirectoryW = moduserenv.NewProc("GetUserProfileDirectoryW")
)

const (
	WTS_CURRENT_SERVER_HANDLE  = 0          // https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw
	CREATE_UNICODE_ENVIRONMENT = 0x00000400 // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
	TokenPrimary               = 1          // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type
	SecurityImpersonation      = 2          // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level
)

const (
	SafeChainProxyBinaryName       = "SafeChainProxy.exe"
	SafeChainProxyLogName          = "SafeChainProxy.log"
	registryInternetSettingsSuffix = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	proxyOverride                  = "<local>,localhost,127.0.0.1"
)

func initConfig() error {
	programDataDir := filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChainAgent")
	config.BinaryDir = `C:\Program Files\AikidoSecurity\SafeChainAgent\bin`
	config.LogDir = filepath.Join(programDataDir, "logs")
	config.RunDir = filepath.Join(programDataDir, "run")

	var err error
	config.HomeDir, err = GetActiveUserHomeDir()
	if err != nil {
		config.HomeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %v", err)
		}
	}
	log.Println("User home directory used for SafeChain:", config.HomeDir)
	safeChainDir := filepath.Join(config.HomeDir, ".safe-chain")
	config.SafeChainBinaryPath = filepath.Join(safeChainDir, "bin", "safe-chain.exe")
	return nil
}

func GetActiveUserHomeDir() (string, error) {
	if !IsWindowsService() {
		return os.UserHomeDir()
	}

	sessionID, err := getActiveUserSessionID()
	if err != nil {
		return "", err
	}

	var userToken windows.Token
	ret, _, err := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&userToken)))
	if ret == 0 {
		return "", fmt.Errorf("WTSQueryUserToken failed: %v", err)
	}
	defer userToken.Close()

	var size uint32
	procGetUserProfileDirectoryW.Call(uintptr(userToken), 0, uintptr(unsafe.Pointer(&size)))

	if size == 0 {
		return "", fmt.Errorf("failed to get profile directory size")
	}

	buf := make([]uint16, size)
	ret, _, err = procGetUserProfileDirectoryW.Call(
		uintptr(userToken),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", fmt.Errorf("GetUserProfileDirectory failed: %v", err)
	}

	return syscall.UTF16ToString(buf), nil
}

// PrepareShellEnvironment sets the PowerShell execution policy to RemoteSigned for the current user.
// This is necessary to allow the safe-chain binary to execute PowerShell scripts during setup,
// such as modifying the PowerShell profile for shell integration.
func PrepareShellEnvironment(ctx context.Context) error {
	return utils.RunCommand(ctx, "powershell", "-Command",
		"Set-ExecutionPolicy", "-ExecutionPolicy", "RemoteSigned", "-Scope", "CurrentUser", "-Force")
}

type syncWriter struct {
	f *os.File
}

func (w *syncWriter) Write(p []byte) (n int, err error) {
	n, err = w.f.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.f.Sync()
}

func SetupLogging() (io.Writer, error) {
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return os.Stdout, err
	}

	logPath := filepath.Join(config.LogDir, "SafeChainAgent.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return os.Stdout, err
	}

	fileWriter := &syncWriter{f: f}
	if IsWindowsService() {
		return fileWriter, nil
	}

	return io.MultiWriter(os.Stdout, fileWriter), nil
}

func getLoggedInUserSIDs(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "reg", "query", "HKU")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var sids []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HKEY_USERS\\") {
			continue
		}
		sid := strings.TrimPrefix(line, "HKEY_USERS\\")
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

func SetSystemProxy(ctx context.Context, proxyURL string) error {
	if err := utils.RunCommand(ctx, "netsh", "winhttp", "set", "proxy", proxyURL); err != nil {
		return err
	}

	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil {
		return err
	}

	for _, sid := range sids {
		regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
		regCmds := [][]string{
			{"reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"},
			{"reg", "add", regPath, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyURL, "/f"},
			{"reg", "add", regPath, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", proxyOverride, "/f"},
		}
		for _, args := range regCmds {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			log.Printf("Running command: %q", strings.Join(args, " "))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return err
			}
		}
	}
	return nil
}

func IsSystemProxySet(ctx context.Context, proxyURL string) bool {
	cmd := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	if strings.Contains(string(output), "Direct access") {
		return false
	}

	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil || len(sids) == 0 {
		return false
	}

	for _, sid := range sids {
		regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
		regCmd := exec.CommandContext(ctx, "reg", "query", regPath, "/v", "ProxyEnable")
		regOutput, err := regCmd.Output()
		if err != nil || !strings.Contains(string(regOutput), "0x1") {
			return false
		}

		regCmd = exec.CommandContext(ctx, "reg", "query", regPath, "/v", "ProxyServer")
		regOutput, err = regCmd.Output()
		if err != nil || !strings.Contains(string(regOutput), proxyURL) {
			return false
		}
	}

	return true
}

func UnsetSystemProxy(ctx context.Context) error {
	if err := utils.RunCommand(ctx, "netsh", "winhttp", "reset", "proxy"); err != nil {
		return err
	}

	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil {
		log.Printf("Warning: failed to get user SIDs: %v", err)
		return err
	}

	for _, sid := range sids {
		regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
		regCmds := [][]string{
			{"reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"},
			{"reg", "delete", regPath, "/v", "ProxyServer", "/f"},
			{"reg", "delete", regPath, "/v", "ProxyOverride", "/f"},
		}
		for _, args := range regCmds {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			log.Printf("Running command: %q", strings.Join(args, " "))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Printf("Warning: failed to run %q: %v", strings.Join(args, " "), err)
			}
		}
	}
	return nil
}

func InstallProxyCA(ctx context.Context, caCertPath string) error {
	return utils.RunCommand(ctx, "certutil", "-addstore", "-f", "Root", caCertPath)
}

func IsProxyCAInstalled(ctx context.Context) bool {
	// certutil returns non-zero exit code if the certificate is not installed
	err := utils.RunCommand(ctx, "certutil", "-store", "Root", "aikido.dev")
	return err == nil
}

func UninstallProxyCA(ctx context.Context) error {
	return utils.RunCommand(ctx, "certutil", "-delstore", "Root", "aikido.dev")
}

type ServiceRunner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type windowsService struct {
	runner ServiceRunner
}

func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		if err := s.runner.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case err := <-errChan:
			log.Printf("Service runner error: %v", err)
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Printf("Received service control: %v", c.Cmd)
				break loop
			default:
				log.Printf("Unexpected service control request: %v", c.Cmd)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := s.runner.Stop(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	return false, 0
}

func IsWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("Failed to determine if running as Windows service: %v", err)
		return false
	}
	return isService
}

func RunAsWindowsService(runner ServiceRunner, serviceName string) error {
	return svc.Run(serviceName, &windowsService{runner: runner})
}

func RunAsCurrentUser(ctx context.Context, binaryPath string, args []string) error {
	if !IsWindowsService() {
		cmd := exec.CommandContext(ctx, binaryPath, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	return runAsLoggedInUser(binaryPath, args)
}

type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

func getActiveUserSessionID() (uint32, error) {
	var sessionInfo uintptr
	var count uint32

	ret, _, err := procWTSEnumerateSessions.Call(
		WTS_CURRENT_SERVER_HANDLE,
		0,
		1,
		uintptr(unsafe.Pointer(&sessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("WTSEnumerateSessions failed: %v", err)
	}
	defer procWTSFreeMemory.Call(sessionInfo)

	sessions := unsafe.Slice((*wtsSessionInfo)(unsafe.Pointer(sessionInfo)), count)
	for _, session := range sessions {
		if session.State == WTS_CURRENT_SERVER_HANDLE && session.SessionID != 0 {
			var token windows.Token
			ret, _, _ := procWTSQueryUserToken.Call(uintptr(session.SessionID), uintptr(unsafe.Pointer(&token)))
			if ret != 0 {
				token.Close()
				return session.SessionID, nil
			}
		}
	}

	return 0, fmt.Errorf("no active user session found")
}

func runAsLoggedInUser(binaryPath string, args []string) error {
	sessionID, err := getActiveUserSessionID()
	if err != nil {
		return err
	}

	log.Printf("Found active user session: %d", sessionID)

	var userToken windows.Token
	ret, _, err := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&userToken)))
	if ret == 0 {
		return fmt.Errorf("WTSQueryUserToken failed: %v", err)
	}
	defer userToken.Close()

	var duplicatedToken windows.Token
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(userToken),
		0,
		0,
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&duplicatedToken)),
	)
	if ret == 0 {
		return fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	defer duplicatedToken.Close()

	var envBlock uintptr
	ret, _, err = procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&envBlock)),
		uintptr(duplicatedToken),
		0,
	)
	if ret == 0 {
		return fmt.Errorf("CreateEnvironmentBlock failed: %v", err)
	}
	defer procDestroyEnvironmentBlock.Call(envBlock)

	cmdLine := binaryPath
	if len(args) > 0 {
		cmdLine = fmt.Sprintf(`"%s" %s`, binaryPath, strings.Join(args, " "))
	} else {
		cmdLine = fmt.Sprintf(`"%s"`, binaryPath)
	}
	cmdLinePtr, _ := syscall.UTF16PtrFromString(cmdLine)

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop, _ = syscall.UTF16PtrFromString("winsta0\\default")

	var pi windows.ProcessInformation

	ret, _, err = procCreateProcessAsUserW.Call(
		uintptr(duplicatedToken),
		0,
		uintptr(unsafe.Pointer(cmdLinePtr)),
		0,
		0,
		0,
		CREATE_UNICODE_ENVIRONMENT,
		envBlock,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessAsUserW failed: %v", err)
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

	log.Printf("Process %s completed successfully as logged-in user", binaryPath)
	return nil
}
