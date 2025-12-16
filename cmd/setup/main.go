package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AikidoSec/safechain-agent/internal/setup"
	"github.com/AikidoSec/safechain-agent/internal/version"
)

func main() {
	var showVersion = flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Print(version.Info())
		os.Exit(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nSetup interrupted.")
		cancel()
	}()

	prompter := setup.NewPrompter(os.Stdin, os.Stdout)
	runner := setup.NewRunner(prompter)

	registerSteps(runner)

	if err := runner.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		os.Exit(1)
	}
}

func registerSteps(runner *setup.Runner) {
}
