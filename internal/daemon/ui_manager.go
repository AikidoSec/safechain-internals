package daemon

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/uiclient"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

// UIManager owns the UI process lifecycle and all outbound daemon→UI
// communication (block notifications, proxy-status updates).
type UIManager struct {
	Client  *uiclient.Client
	process uiProcess

	lastProxyStatus        bool
	proxyStatusInitialized bool
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

	token := m.Client.GenerateAndSetToken()
	daemonURL := "http://" + ingressAddr

	port, err := utils.GetRandomFreePort()
	if err != nil {
		return fmt.Errorf("failed to get random free port: %v", err)
	}
	uiURL := fmt.Sprintf("127.0.0.1:%d", port)
	m.Client.SetBaseURL(uiURL)

	cfg := platform.GetConfig()
	binaryPath := filepath.Join(cfg.BinaryDir, platform.SafeChainUIAppName)
	args := []string{
		"--daemon_url", daemonURL,
		"--token", token,
		"--ui_url", uiURL,
		"--log_file", platform.GetUILogPath(),
	}

	log.Printf("Launching UI with args: --daemon_url %s --token *** --ui_url %s --log_file %s", daemonURL, uiURL, platform.GetUILogPath())
	pid, err := platform.StartUIProcessInAuditSessionOfCurrentUser(ctx, binaryPath, args)
	if pid > 0 {
		m.process.setPID(pid)
		log.Printf("UI process PID: %d", pid)
	}
	if err != nil {
		return fmt.Errorf("failed to launch UI: %v", err)
	}
	log.Println("UI tray application launched")
	return nil
}

// Kill terminates the UI process if it was started.
func (m *UIManager) Kill() {
	m.process.Kill()
}

// NotifyProxyStatusIfChanged sends a proxy-status update to the UI only when
// the running state has changed (or on the very first call).
func (m *UIManager) NotifyProxyStatusIfChanged(running bool) {
	if !m.proxyStatusInitialized || m.lastProxyStatus != running {
		if err := m.Client.NotifyProxyStatus(running); err != nil {
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
