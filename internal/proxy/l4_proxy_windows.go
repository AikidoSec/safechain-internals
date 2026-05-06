//go:build windows

package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	l4ReadyTimeout  = 60 * time.Second
	l4ReadyInterval = 1 * time.Second
	l4StopTimeout   = 10 * time.Second

	// Subdirectory under platform.GetRunDir() where the Rust L4 proxy stores
	// its data (agent identity, listener address files, etc.).
	l4DataSubdir = "safechain-l4-proxy"

	// File the Rust L4 proxy writes its bound IPv4 listener address to once
	// it has both bound the TCP socket AND successfully registered with the
	// SafeChain L4 kernel driver via the driver-object IPC. We poll for it as
	// our readiness signal.
	l4AddrV4FileName = "l4_proxy.addr.v4.txt"

	// Bind to a kernel-assigned port on loopback. The kernel WFP driver
	// learns the actual port via the driver-object IPC handshake, so we
	// don't need a fixed port like the L7 proxy does.
	l4DefaultBindIPv4 = "127.0.0.1:0"

	// Probe timeouts kept short so IsRunning stays cheap even when called
	// from health-check / status loops.
	l4DialProbeTimeout = 500 * time.Millisecond
)

// L4Proxy supervises the user-mode SafeChainL4Proxy.exe process. The proxy is
// a long-running TCP listener that opens the kernel-mode SafeChainL4Proxy
// device, which causes the WFP filter driver to load and engage redirection.
//
// Unlike the macOS implementation, on Windows there is no separate
// "install-extension" / "is-extension-installed" flow: the kernel driver is
// installed via the MSI (pnputil /add-driver) and is loaded on demand the
// first time the user-mode proxy opens \\.\SafechainL4Proxy.
type L4Proxy struct {
	cmd        *exec.Cmd
	ctx        context.Context
	cancel     context.CancelFunc
	procDone   chan struct{}
	procErr    error
	listenAddr string
}

func NewL4() *L4Proxy {
	return &L4Proxy{}
}

func (p *L4Proxy) binaryPath() string {
	return filepath.Join(platform.GetConfig().BinaryDir, platform.SafeChainL4ProxyBinaryName)
}

func (p *L4Proxy) dataDir() string {
	return filepath.Join(platform.GetRunDir(), l4DataSubdir)
}

func (p *L4Proxy) addrFilePath() string {
	return filepath.Join(p.dataDir(), l4AddrV4FileName)
}

func (p *L4Proxy) Start(ctx context.Context, opts StartOptions) error {
	cfg := platform.GetConfig()

	dataDir := p.dataDir()
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create L4 proxy data dir %s: %w", dataDir, err)
	}
	// Clear any stale addr file from a previous run so the readiness wait
	// only observes a value written by the current process.
	if err := os.Remove(p.addrFilePath()); err != nil && !os.IsNotExist(err) {
		log.Printf("L4 proxy: failed to remove stale addr file: %v", err)
	}

	args := []string{
		"--bind-ipv4", l4DefaultBindIPv4,
		"--data", dataDir,
		"--output", filepath.Join(cfg.LogDir, platform.SafeChainL4ProxyLogName),
		"--secrets", "keyring",
	}
	if opts.IngressAddr != "" {
		args = append(args, "--reporting-endpoint", fmt.Sprintf("http://%s", opts.IngressAddr))
	}
	if opts.BaseURL != "" {
		args = append(args, "--aikido-url", opts.BaseURL)
	}
	if opts.Passthrough {
		// The Windows L4 proxy has no equivalent of the macOS --no-firewall
		// flag yet; passthrough mode is a no-op here. Surface this clearly
		// so it's obvious in logs why blocking still applies.
		log.Println("L4 proxy: passthrough mode requested but not supported on Windows; firewalling remains active")
	}
	if opts.Token != "" || opts.DeviceID != "" {
		// On Windows the proxy loads agent identity from its --data dir; the
		// CLI flags accepted by the macOS variant don't exist here.
		log.Println("L4 proxy: agent token/device id are loaded from data directory on Windows; CLI args ignored")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.cmd = exec.CommandContext(p.ctx, p.binaryPath(), args...)

	stderrLogPath := filepath.Join(cfg.LogDir, platform.SafeChainL4ProxyErrLogName)
	stderrFile, err := os.OpenFile(stderrLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open L4 proxy stderr log file: %w", err)
	}
	p.cmd.Stdout = stderrFile
	p.cmd.Stderr = stderrFile

	log.Println("Starting SafeChain L4 Proxy:", p.cmd.String())
	if err := p.cmd.Start(); err != nil {
		_ = stderrFile.Close()
		return fmt.Errorf("failed to start L4 proxy: %w", err)
	}

	p.procDone = make(chan struct{})
	go func() {
		p.procErr = p.cmd.Wait()
		_ = stderrFile.Close()
		close(p.procDone)
	}()

	addr, err := p.waitForReady()
	if err != nil {
		return fmt.Errorf("L4 transparent proxy did not start at this time, but will be retried by the daemon: %w", err)
	}
	p.listenAddr = addr

	log.Printf("SafeChain L4 Proxy started successfully (listening on %s)", addr)
	return nil
}

// waitForReady blocks until the L4 proxy has written its addr file AND we can
// TCP-dial the advertised address, or until the process exits / we time out.
//
// The Rust binary writes the addr file LAST (after binding the TCP socket and
// after successfully registering with the kernel driver via the driver-object
// IPC), so observing the file is a strong "fully ready" signal. We still dial
// the port to guard against races on slower disks.
func (p *L4Proxy) waitForReady() (string, error) {
	if p.procDone == nil {
		return "", fmt.Errorf("procDone channel is nil")
	}

	timeout := time.After(l4ReadyTimeout)
	ticker := time.NewTicker(l4ReadyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return "", fmt.Errorf("timeout waiting for L4 proxy to be ready after %s", l4ReadyTimeout)
		case <-p.procDone:
			return "", fmt.Errorf("L4 proxy process exited unexpectedly: %v", p.procErr)
		case <-ticker.C:
			content, err := os.ReadFile(p.addrFilePath())
			if err != nil {
				continue
			}
			addr := strings.TrimSpace(string(content))
			if addr == "" {
				continue
			}
			conn, dialErr := net.DialTimeout("tcp", addr, l4DialProbeTimeout)
			if dialErr != nil {
				continue
			}
			_ = conn.Close()
			return addr, nil
		}
	}
}

func (p *L4Proxy) Stop() error {
	log.Println("Stopping SafeChain L4 Proxy...")
	if p.cancel != nil {
		p.cancel()
	}
	if p.procDone != nil {
		select {
		case <-p.procDone:
		case <-time.After(l4StopTimeout):
			log.Println("Timeout waiting for L4 proxy process to exit, killing...")
			if p.cmd != nil && p.cmd.Process != nil {
				if err := p.cmd.Process.Kill(); err != nil {
					log.Printf("Failed to kill L4 proxy process: %v", err)
				}
			}
		}
	}
	log.Println("SafeChain L4 Proxy stopped successfully!")
	return nil
}

func (p *L4Proxy) IsRunning() bool {
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	if p.procDone != nil {
		select {
		case <-p.procDone:
			return false
		default:
		}
	}
	if !platform.IsProcessAlive(p.cmd.Process.Pid) {
		return false
	}
	if p.listenAddr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", p.listenAddr, l4DialProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (p *L4Proxy) InstallCA(ctx context.Context) error {
	return InstallL4ProxyCA(ctx)
}

func (p *L4Proxy) Version() (string, error) {
	cmd := exec.Command(p.binaryPath(), "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get L4 proxy version: %w", err)
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return "", fmt.Errorf("L4 proxy version output is empty")
	}
	parts := strings.Fields(trimmed)
	return parts[len(parts)-1], nil
}

func (p *L4Proxy) GetStatus() (bool, string) {
	if p.IsRunning() {
		return true, "connected"
	}
	if p.cmd == nil {
		return false, "not-installed"
	}
	if p.procErr != nil {
		return false, fmt.Sprintf("exited: %v", p.procErr)
	}
	return false, "disconnected"
}
