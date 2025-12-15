package proxy

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/aikido/safechain-agent/internal/platform"
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
	p.ctx, p.cancel = context.WithCancel(ctx)

	cfg := platform.Get()
	p.cmd = exec.CommandContext(p.ctx, cfg.SafeChainBinary, "run-proxy")
	p.cmd.Stdout = os.Stdout
	p.cmd.Stderr = os.Stderr

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	log.Printf("Proxy started (pid: %d)", p.cmd.Process.Pid)

	go func() {
		if err := p.cmd.Wait(); err != nil {
			if p.ctx.Err() == nil {
				log.Printf("Proxy process exited with error: %v", err)
			}
		}
	}()

	return nil
}

func (p *Proxy) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}

	if p.cmd != nil && p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err != nil {
			log.Printf("Failed to kill proxy process: %v", err)
		}
	}

	log.Println("Proxy stopped")
	return nil
}
