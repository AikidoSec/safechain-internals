package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AikidoSec/safechain-agent/internal/setup"
	install_proxy_ca "github.com/AikidoSec/safechain-agent/internal/setup/steps/01_install_proxy_ca"
	set_system_proxy "github.com/AikidoSec/safechain-agent/internal/setup/steps/02_set_system_proxy"
)

func main() {
	uninstallFlag := flag.Bool("uninstall", false, "Run in uninstall mode")
	flag.Parse()
	uninstall := *uninstallFlag

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)

	// Subscribe to SIGINT, SIGTERM, and SIGQUIT signals
	// These signals are received via sigChan and are used to trigger a graceful shutdown of the setup
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sigChan
		fmt.Println("\nSetup interrupted.")
		cancel()
	}()

	prompter := setup.NewPrompter(os.Stdin, os.Stdout)
	runner := setup.NewRunner(prompter, uninstall)

	registerSteps(runner)

	if err := runner.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		os.Exit(1)
	}
}

func registerSteps(runner *setup.Runner) {
	runner.AddStep(install_proxy_ca.New(runner.Uninstall))
	runner.AddStep(set_system_proxy.New(runner.Uninstall))
}
