package proxy

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

const (
	ProxyBind    = "127.0.0.1:0"
	ProxyMeta    = "127.0.0.1:0"
	ProxySecrets = ".aikido/safechain-proxy"
)

var (
	ProxyHttpUrl  string
	ProxyHttpsUrl string
	MetaHttpUrl   string
	MetaHttpsUrl  string
)

type Proxy struct {
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
}

func New() *Proxy {
	return &Proxy{}
}

func (p *Proxy) Start(ctx context.Context) error {
	log.Println("Starting Safe Chain Proxy...")

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.cmd = exec.CommandContext(p.ctx,
		"safechain-proxy",
		"--bind", ProxyBind,
		"--meta", ProxyMeta,
		"--secrets", ProxySecrets,
	)

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %v", err)
	}
	// Wait for proxy to be ready
	log.Println("Waiting for proxy to be ready...")
	time.Sleep(5 * time.Second) // temp

	var err error
	ProxyHttpUrl, ProxyHttpsUrl, err = GetProxyUrl()
	if err != nil {
		return fmt.Errorf("failed to get proxy url: %v", err)
	}
	MetaHttpUrl, MetaHttpsUrl, err = GetMetaUrl()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	log.Println("Proxy URL:", ProxyHttpUrl)
	log.Println("Meta URL:", MetaHttpUrl)

	if err := Check(); err != nil {
		return fmt.Errorf("failed to check proxy: %v", err)
	}

	log.Println("Safe Chain Proxy started successfully!")
	return nil
}

func (p *Proxy) Stop() error {
	log.Println("Stopping Safe Chain Proxy...")
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		if err := p.cmd.Wait(); err != nil {
			return fmt.Errorf("failed to wait for proxy: %v", err)
		}
	}

	log.Println("Safe Chain Proxy stopped successfully!")
	return nil
}
