package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/daemon"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

const serviceName = "SafeChainUltimate"

func main() {
	var (
		showVersion    = flag.Bool("version", false, "Show version information")
		teardown       = flag.Bool("teardown", false, "Teardown SafeChain Ultimate")
		removeScanners = flag.Bool("remove-scanners", false, "Remove all scanners on teardown")
	)
	flag.Parse()

	if *showVersion {
		fmt.Print(version.Info.String())
		os.Exit(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := daemon.New(ctx, cancel, &daemon.Config{})
	if err != nil {
		log.Fatalf("Failed to create daemon: %v", err)
	}

	if *teardown {
		if err := d.Uninstall(ctx, *removeScanners); err != nil {
			log.Fatalf("Failed to teardown daemon: %v", err)
		}
		return
	}

	if platform.IsWindowsService() {
		if err := platform.RunAsWindowsService(d, serviceName); err != nil {
			log.Fatalf("Failed to run as Windows service: %v", err)
		}
		return
	}

	runConsoleMode(ctx, cancel, d)
}

func runConsoleMode(ctx context.Context, cancel context.CancelFunc, d *daemon.Daemon) {
	log.Println("Running in console mode...")

	// Subscribes to SIGINT, SIGTERM, and SIGQUIT signals
	// These signals are received via sigChan and are used to trigger a graceful shutdown of the daemon
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	errChan := make(chan error, 1)
	go func() {
		if err := d.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v, shutting down gracefully...", sig)
	case err := <-errChan:
		log.Printf("Daemon error: %v, shutting down gracefully...", err)
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := d.Stop(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
	log.Println("Daemon stopped")
}
