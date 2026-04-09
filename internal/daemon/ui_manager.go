package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/uiclient"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const uiReadyTimeout = 5 * time.Second

// UIManager owns the UI process lifecycle and all outbound daemon→UI
// communication (block notifications, proxy-status updates).
type UIManager struct {
	Client  *uiclient.Client
	process uiProcess

	launchMu    sync.Mutex
	ctx         context.Context
	ingressAddr string

	lastProxyStatus        bool
	proxyStatusInitialized bool
	lastProxyStdoutMessage string

	certPromptMu                        sync.Mutex
	certificateInstallPromptAlreadySent bool
}

func NewUIManager() *UIManager {
	return &UIManager{
		Client: uiclient.New(),
	}
}

// Launch starts the UI tray application, generating a shared auth token and
// picking a free port for the UI server. The ingress address is passed so the
// UI can call back into the daemon.
func (m *UIManager) Launch(ctx context.Context, ingressAddr string) error {
	if ingressAddr == "" {
		return fmt.Errorf("ingress server address not available")
	}

	m.launchMu.Lock()
	defer m.launchMu.Unlock()
	m.ctx = ctx
	m.ingressAddr = ingressAddr
	return m.spawnUI(ctx, ingressAddr)
}

// spawnUI does the actual work of starting a new UI process.
// Must be called with launchMu held.
func (m *UIManager) spawnUI(ctx context.Context, ingressAddr string) error {
	token := m.Client.GenerateAndSetToken()
	daemonURL := "http://" + ingressAddr

	port, err := utils.GetRandomFreePort()
	if err != nil {
		return fmt.Errorf("failed to get random free port: %v", err)
	}
	uiURL := fmt.Sprintf("127.0.0.1:%d", port)
	m.Client.SetBaseURL(uiURL)

	binaryPath := platform.GetUIAppPath()
	args := []string{
		"--daemon_url", daemonURL,
		"--token", token,
		"--ui_url", uiURL,
		"--log_file", platform.GetUILogPath(),
	}

	log.Printf("Launching UI with args: --daemon_url %s --token *** --ui_url %s --log_file %s", daemonURL, uiURL, platform.GetUILogPath())
	pid, err := platform.StartUIProcessInAuditSessionOfCurrentUser(ctx, binaryPath, args)
	if err != nil {
		return fmt.Errorf("failed to launch UI: %v", err)
	}
	log.Printf("UI process PID: %d", pid)
	m.process.setPID(pid)
	log.Println("UI tray application launched")
	return nil
}

// EnsureRunning checks whether the UI process is still alive and relaunches
// it if the user (or the OS) has stopped it. Safe to call from multiple
// goroutines; concurrent relaunches are serialized by launchMu.
func (m *UIManager) EnsureRunning() {
	if m.process.isAlive() {
		return
	}

	m.launchMu.Lock()
	defer m.launchMu.Unlock()

	// Re-check under the lock — another goroutine (or the initial Launch)
	// may have started the process while we were waiting for the mutex.
	if m.process.isAlive() {
		return
	}

	ctx := m.ctx
	ingressAddr := m.ingressAddr
	if ctx == nil || ingressAddr == "" || ctx.Err() != nil {
		return
	}

	log.Println("UI process not running, relaunching...")
	if err := m.spawnUI(ctx, ingressAddr); err != nil {
		log.Printf("Failed to relaunch UI: %v", err)
		return
	}
	m.waitForUIReady()
	m.proxyStatusInitialized = false
	m.certificateInstallPromptAlreadySent = false
}

// waitForUIReady polls the UI's HTTP port until it accepts TCP connections
// or the timeout elapses. This avoids "connection refused" errors when
// notifications are sent right after a relaunch.
func (m *UIManager) waitForUIReady() {
	raw := m.Client.BaseURL()
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	addr := u.Host

	deadline := time.Now().Add(uiReadyTimeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Printf("UI did not become ready within %s", uiReadyTimeout)
}

// Kill terminates the UI process if it was started.
func (m *UIManager) Kill() {
	m.process.Kill()
}

// Token returns the shared auth token used by the UI.
func (m *UIManager) Token() string {
	return m.Client.Token()
}

// NotifyBlocked ensures the UI is running, then sends a block notification.
func (m *UIManager) NotifyBlocked(ev any) {
	m.Client.NotifyBlocked(ev)
}

// NotifyTlsTerminationFailed sends a TLS termination failure notification to the UI.
func (m *UIManager) NotifyTlsTerminationFailed(ev any) {
	m.Client.NotifyTlsTerminationFailed(ev)
}

// NotifyPermissionsUpdated sends the latest permissions to the UI.
func (m *UIManager) NotifyPermissionsUpdated(perms any) {
	m.Client.NotifyPermissionsUpdated(perms)
}

// NotifyCertificateInstallPromptIfChanged notifies the tray UI to show the install
// window when the CA is missing. It never requests a hide: the user closes the
// window with Done after finishing the wizard.
func (m *UIManager) NotifyCertificateInstallPromptIfChanged(needed bool) {
	m.certPromptMu.Lock()
	defer m.certPromptMu.Unlock()
	if !needed {
		m.certificateInstallPromptAlreadySent = false
		return
	}
	if m.certificateInstallPromptAlreadySent {
		return
	}
	log.Println("Proxy CA not installed; tray app will prompt the user to complete installation")
	m.certificateInstallPromptAlreadySent = true
	if err := m.Client.NotifyCertificateInstallPrompt(true); err != nil {
		log.Printf("Failed to notify UI of certificate install prompt: %v", err)
	}
}

// NotifyProxyStatusIfChanged sends a proxy-status update to the UI only when
// the running state has changed (or on the very first call).
func (m *UIManager) NotifyProxyStatusIfChanged(running bool, stdoutMessage string) {
	if !m.proxyStatusInitialized || m.lastProxyStatus != running || m.lastProxyStdoutMessage != stdoutMessage {
		if err := m.Client.NotifyProxyStatus(running, stdoutMessage); err != nil {
			log.Printf("Failed to send proxy-status to UI: %v", err)
			return
		}
		m.lastProxyStatus = running
		m.proxyStatusInitialized = true
	}
}

// uiProcess holds the tray UI process PID so the daemon can kill it on Stop.
type uiProcess struct {
	mu  sync.Mutex
	pid int
}

func (u *uiProcess) setPID(pid int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.pid = pid
}

func (u *uiProcess) isAlive() bool {
	u.mu.Lock()
	pid := u.pid
	u.mu.Unlock()
	if pid <= 0 {
		return false
	}
	return platform.IsProcessAlive(pid)
}

func (u *uiProcess) Kill() {
	u.mu.Lock()
	pid := u.pid
	u.pid = 0
	u.mu.Unlock()
	if pid <= 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("Failed to find UI process %d: %v", pid, err)
		return
	}
	if err := proc.Kill(); err != nil {
		log.Printf("Failed to kill UI process %d: %v", pid, err)
		return
	}
	log.Printf("Stopped UI tray process (PID %d)", pid)
}
