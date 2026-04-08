//go:build darwin

package proxy

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	l4ReadyTimeout  = 30 * time.Second
	l4ReadyInterval = 1 * time.Second
)

type L4Proxy struct {
	startStdoutMessage string
}

func NewL4() *L4Proxy {
	return &L4Proxy{}
}

func (p *L4Proxy) Start(ctx context.Context, opts StartOptions) error {
	args := []string{"start"}

	if opts.IngressAddr != "" {
		args = append(args, "--reporting-endpoint", fmt.Sprintf("http://%s", opts.IngressAddr))
	}
	if opts.BaseURL != "" {
		args = append(args, "--aikido-url", opts.BaseURL)
	}
	if opts.Token != "" && opts.DeviceID != "" {
		args = append(args, "--agent-token", opts.Token, "--agent-device-id", opts.DeviceID)
	}

	log.Printf("Starting L4 transparent proxy: %s %s", platform.SafeChainL4ProxyHostPath, strings.Join(args, " "))

	output, _ := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, args)
	outputStr := strings.TrimSpace(output)
	p.startStdoutMessage = outputStr

	log.Printf("L4 proxy start output: %s", outputStr)

	if strings.Contains(outputStr, "status: connected") {
		log.Println("L4 transparent proxy started successfully")
		return nil
	}
	return fmt.Errorf("L4 transparent proxy did not start at this time, but will be retried by the daemon")
}

func (p *L4Proxy) Stop() error {
	// L4 proxy does not need to be stopped when daemon exits
	// It will be stopped on pkg uninstall
	return nil
}

func (p *L4Proxy) IsRunning() bool {
	cmd := exec.Command(platform.SafeChainL4ProxyHostPath, "status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("L4 proxy status check failed: %v", err)
		return false
	}
	return strings.Contains(string(output), "status: connected")
}

func (p *L4Proxy) InstallCA(ctx context.Context) error {
	return InstallL4ProxyCA(ctx)
}

func (p *L4Proxy) Version() (string, error) {
	return "l4-transparent", nil
}

func (p *L4Proxy) GetStatus() (bool, string) {
	isRunning := p.IsRunning()
	if isRunning {
		return isRunning, "connected"
	}
	statusMessage := p.startStdoutMessage
	if strings.Contains(p.startStdoutMessage, "status:") {
		statusMessage = strings.Replace(statusMessage, "status: ", "", 1)
	}
	if statusMessage == "" {
		statusMessage = "not-installed"
	}
	return isRunning, statusMessage
}
