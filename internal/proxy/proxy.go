package proxy

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

const (
	ProxyBind          = "127.0.0.1:7654"
	ProxyMeta          = "127.0.0.1:7655" // This hosts the proxy's CA and is also useful for health checks
	ProxyReadyTimeout  = 10 * time.Second
	ProxyReadyInterval = 1 * time.Second
)

type Proxy struct {
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
}

func New() *Proxy {
	return &Proxy{}
}

func (p *Proxy) WaitForProxyToBeReady() error {
	timeout := time.After(ProxyReadyTimeout)
	ticker := time.NewTicker(ProxyReadyInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for proxy to be ready after %s", ProxyReadyTimeout.String())
		case <-ticker.C:
			err := LoadProxyConfig()
			if err == nil {
				return nil
			}
		}
	}
}

func (p *Proxy) Start(ctx context.Context, proxyIngressAddr string) error {
	config := platform.GetConfig()
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.cmd = exec.CommandContext(p.ctx,
		filepath.Join(config.BinaryDir, platform.SafeChainProxyBinaryName),
		"--bind", ProxyBind,
		"--meta", ProxyMeta,
		"--data", platform.GetRunDir(),
		"--output", filepath.Join(config.LogDir, platform.SafeChainProxyLogName),
		"--secrets", "keyring",
	)

	log.Println("Starting SafeChain Proxy with command:", p.cmd.String())

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %v", err)
	}

	log.Println("Waiting for proxy to be ready...")
	if err := p.WaitForProxyToBeReady(); err != nil {
		return fmt.Errorf("failed to wait for proxy to be ready: %v", err)
	}

	log.Println("Proxy URL:", ProxyHttpUrl)
	log.Println("Meta URL:", MetaHttpUrl)
	log.Println("SafeChain Proxy started successfully!")
	return nil
}

func (p *Proxy) IsProxyRunning() bool {
	return IsProxyRunning()
}

func (p *Proxy) Stop() error {
	log.Println("Stopping SafeChain Proxy...")
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Wait()
	}

	log.Println("SafeChain Proxy stopped successfully!")
	return nil
}
