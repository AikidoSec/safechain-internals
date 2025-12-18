package daemon

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/AikidoSec/safechain-agent/internal/constants"
	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/proxy"
	"github.com/AikidoSec/safechain-agent/internal/scannermanager"
	"github.com/AikidoSec/safechain-agent/internal/version"
)

type Config struct {
	ConfigPath string
	LogLevel   string
}

type Daemon struct {
	config   *Config
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once
	proxy    *proxy.Proxy
	registry *scannermanager.Registry
}

func New(ctx context.Context, cancel context.CancelFunc, config *Config) (*Daemon, error) {
	d := &Daemon{
		ctx:      ctx,
		cancel:   cancel,
		config:   config,
		proxy:    proxy.New(),
		registry: scannermanager.NewRegistry(),
	}

	d.initLogging()
	return d, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	log.Print("Starting Safe Chain Daemon:\n", version.Info())

	mergedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-d.ctx.Done():
			cancel()
		case <-mergedCtx.Done():
		}
	}()

	d.wg.Add(1)
	go d.run(mergedCtx)

	<-mergedCtx.Done()

	log.Println("Safe Chain Daemon main loop stopped")
	d.wg.Wait()
	return nil
}

func (d *Daemon) Stop(ctx context.Context) error {
	var err error
	d.stopOnce.Do(func() {
		log.Println("Stopping Safe Chain Daemon...")

		if err := d.registry.UninstallAll(ctx); err != nil {
			log.Printf("Error uninstalling scanners: %v", err)
		}

		if stopErr := d.proxy.Stop(); stopErr != nil {
			log.Printf("Error stopping proxy: %v", stopErr)
		}

		d.cancel()

		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("Safe Chain Daemon stopped successfully")
		case <-ctx.Done():
			err = fmt.Errorf("timeout waiting for daemon to stop")
			log.Println("Timeout waiting for daemon to stop")
		}
	})
	return err
}

func (d *Daemon) run(ctx context.Context) {
	defer d.wg.Done()

	ticker := time.NewTicker(constants.HeartbeatInterval)
	defer ticker.Stop()

	log.Println("Daemon is running...")

	if err := d.proxy.Start(ctx); err != nil {
		log.Printf("Failed to start proxy: %v", err)
		return
	}

	if err := d.registry.InstallAll(ctx); err != nil {
		log.Printf("Failed to install all scanners: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping daemon loop")
			return
		case <-ticker.C:
			d.heartbeat()
		}
	}
}

func (d *Daemon) heartbeat() {
	// To add periodic checks for the daemon and scanners
}

func (d *Daemon) initLogging() {
	writer, err := platform.SetupLogging()
	if err != nil {
		log.Printf("Failed to setup file logging: %v, using stdout only", err)
	}
	log.SetOutput(writer)
	log.SetFlags(log.LstdFlags)
}
