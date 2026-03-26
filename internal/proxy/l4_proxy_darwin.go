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

type L4Proxy struct{}

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

	cmd := exec.CommandContext(ctx, platform.SafeChainL4ProxyHostPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start L4 proxy: %v, output: %s", err, string(output))
	}

	outputStr := strings.TrimSpace(string(output))
	log.Printf("L4 proxy start output: %s", outputStr)

	if strings.Contains(outputStr, "status: connected") {
		log.Println("L4 transparent proxy started successfully")
		return nil
	}

	timeout := time.After(l4ReadyTimeout)
	ticker := time.NewTicker(l4ReadyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for L4 proxy to reach connected state")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if p.IsRunning() {
				log.Println("L4 transparent proxy started successfully")
				return nil
			}
		}
	}
}

func (p *L4Proxy) Stop() error {
	log.Println("Stopping L4 transparent proxy...")

	cmd := exec.Command(platform.SafeChainL4ProxyHostPath, "stop")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop L4 proxy: %v, output: %s", err, string(output))
	}

	log.Printf("L4 proxy stop output: %s", strings.TrimSpace(string(output)))
	log.Println("L4 transparent proxy stopped successfully")
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

func (p *L4Proxy) Version() (string, error) {
	return "l4-transparent", nil
}
