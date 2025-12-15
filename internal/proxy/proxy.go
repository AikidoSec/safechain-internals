package proxy

import (
	"context"
	"os/exec"
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
	return nil
}

func (p *Proxy) Stop() error {
	return nil
}
