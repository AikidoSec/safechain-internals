package proxy

import "context"

type ProxyManager interface {
	Start(ctx context.Context, opts StartOptions) error
	Stop() error
	IsRunning() bool
	Version() (string, error)
	InstallCA(ctx context.Context) error
}

type StartOptions struct {
	IngressAddr string
	BaseURL     string
	Token       string
	DeviceID    string
}
