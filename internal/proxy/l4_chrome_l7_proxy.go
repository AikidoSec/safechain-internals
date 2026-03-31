package proxy

import (
	"context"
	"log"
)

// L4ChromeL7Proxy runs both the L4 transparent proxy and the L7 proxy
// simultaneously. L4 handles all non-Chrome traffic; L7 is configured
// only for Chrome via a managed browser policy (no system PAC).
type L4ChromeL7Proxy struct {
	l4 *L4Proxy
	l7 *L7Proxy
}

func NewL4ChromeL7() *L4ChromeL7Proxy {
	return &L4ChromeL7Proxy{
		l4: NewL4(),
		l7: NewL7(),
	}
}

func (p *L4ChromeL7Proxy) Start(ctx context.Context, opts StartOptions) error {
	if err := p.l7.Start(ctx, opts); err != nil {
		return err
	}
	if err := p.l4.Start(ctx, opts); err != nil {
		log.Printf("L4 proxy failed to start (will be retried): %v", err)
	}
	return nil
}

func (p *L4ChromeL7Proxy) Stop() error {
	if err := p.l7.Stop(); err != nil {
		log.Printf("Error stopping L7 proxy: %v", err)
	}
	if err := p.l4.Stop(); err != nil {
		log.Printf("Error stopping L4 proxy: %v", err)
	}
	return nil
}

func (p *L4ChromeL7Proxy) IsRunning() bool {
	return p.l7.IsRunning()
}

func (p *L4ChromeL7Proxy) Version() (string, error) {
	return p.l7.Version()
}

func (p *L4ChromeL7Proxy) InstallCA(ctx context.Context) error {
	// L4's CA is installed as the primary cert (written to GetCaCertPath) so that
	// ecosystem tools (npm, pip, vscode) that go through L4 have their trust
	// bundles configured correctly.
	if err := p.l4.InstallCA(ctx); err != nil {
		return err
	}
	// L7's CA must also be trusted so Chrome (which goes through L7) can verify
	// L7's MITM certificates. Download and install it directly into the OS
	// keychain without overwriting the L4 cert at GetCaCertPath.
	return InstallL7ProxyCAAsAdditional(ctx)
}

func (p *L4ChromeL7Proxy) GetStatus() (bool, string) {
	return p.l7.GetStatus()
}
