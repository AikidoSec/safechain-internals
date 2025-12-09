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

	"github.com/aikido/sc-agent/internal/daemon"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	var (
		configPath  = flag.String("config", "", "Path to configuration file")
		logLevel    = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("sc-agent version %s\n", version)
		fmt.Printf("Build time: %s\n", buildTime)
		fmt.Printf("Git commit: %s\n", gitCommit)
		os.Exit(0)
	}

	d, err := daemon.New(&daemon.Config{
		ConfigPath: *configPath,
		LogLevel:   *logLevel,
	})
	if err != nil {
		log.Fatalf("Failed to create daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
