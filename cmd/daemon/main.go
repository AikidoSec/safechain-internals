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

	"github.com/AikidoSec/safechain-agent/internal/daemon"
	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/version"
)

const serviceName = "SafeChainAgent"

func main() {
	var (
		configPath  = flag.String("config", "", "Path to configuration file")
		logLevel    = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Print(version.Info())
		os.Exit(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := daemon.New(ctx, cancel, &daemon.Config{
		ConfigPath: *configPath,
		LogLevel:   *logLevel,
	})
	if err != nil {
		log.Fatalf("Failed to create daemon: %v", err)
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
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if err := d.Stop(shutdownCtx); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	case err := <-errChan:
		log.Fatalf("Daemon error: %v", err)
	}

	log.Println("Daemon stopped")
}
