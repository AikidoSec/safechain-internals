package proxy

import (
	"context"
	"log"
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
	log.Println("Starting SafeChain Agent proxy...")
	return nil
}

func (p *Proxy) Stop() error {
	log.Println("Stopping SafeChain Agent proxy...")
	return nil
}
