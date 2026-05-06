//go:build !darwin && !windows

package proxy

import (
	"context"
	"fmt"
)

type L4Proxy struct{}

func NewL4() *L4Proxy {
	return &L4Proxy{}
}

func (p *L4Proxy) Start(_ context.Context, _ StartOptions) error {
	return fmt.Errorf("L4 transparent proxy is only supported on macOS")
}

func (p *L4Proxy) Stop() error {
	return fmt.Errorf("L4 transparent proxy is only supported on macOS")
}

func (p *L4Proxy) IsRunning() bool {
	return false
}

func (p *L4Proxy) InstallCA(_ context.Context) error {
	return fmt.Errorf("L4 transparent proxy is only supported on macOS")
}

func (p *L4Proxy) Version() (string, error) {
	return "", fmt.Errorf("L4 transparent proxy is only supported on macOS")
}

func (p *L4Proxy) GetStatus() (bool, string) {
	return false, "disconnected"
}
