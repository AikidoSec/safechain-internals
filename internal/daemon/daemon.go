package daemon

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/constants"
	"github.com/AikidoSec/safechain-internals/internal/ingress"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
	"github.com/AikidoSec/safechain-internals/internal/scannermanager"
	"github.com/AikidoSec/safechain-internals/internal/setup"
	"github.com/AikidoSec/safechain-internals/internal/utils"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

type Config struct {
	ConfigPath string
	LogLevel   string
}

type Daemon struct {
	config     *Config
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stopOnce   sync.Once
	proxy      *proxy.Proxy
	registry   *scannermanager.Registry
	ingress    *ingress.Server
	logRotator *utils.LogRotator
	logReaper  *utils.LogReaper
}

func New(ctx context.Context, cancel context.CancelFunc, config *Config) (*Daemon, error) {
	d := &Daemon{
		ctx:        ctx,
		cancel:     cancel,
		config:     config,
		proxy:      proxy.New(),
		registry:   scannermanager.NewRegistry(),
		ingress:    ingress.New(),
		logRotator: utils.NewLogRotator(),
		logReaper:  utils.NewLogReaper(),
	}

	if err := platform.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize platform: %v", err)
	}

	d.initLogging()
	return d, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	log.Print("Starting SafeChain Daemon:\n", version.Info())
	log.Println("User home directory used for SafeChain:", platform.GetConfig().HomeDir)

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
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.run(mergedCtx)
	}()

	select {
	case <-mergedCtx.Done():
		log.Println("SafeChain Daemon main loop stopped")
	case err := <-errCh:
		if err != nil {
			d.wg.Wait()
			return err
		}
	}

	d.wg.Wait()
	return nil
}

func (d *Daemon) Stop(ctx context.Context) error {
	var err error
	d.stopOnce.Do(func() {
		log.Println("Stopping SafeChain Daemon...")

		if err := setup.Teardown(ctx); err != nil {
			log.Printf("Error teardown setup: %v", err)
		}

		if err := d.proxy.Stop(); err != nil {
			log.Printf("Error stopping proxy: %v", err)
		}

		if err := d.ingress.Stop(); err != nil {
			log.Printf("Error stopping ingress server: %v", err)
		}

		d.cancel()

		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("SafeChain Daemon stopped successfully")
		case <-ctx.Done():
			err = fmt.Errorf("timeout waiting for daemon to stop")
			log.Println("Timeout waiting for daemon to stop")
		}
	})
	return err
}

func (d *Daemon) run(ctx context.Context) error {
	defer d.wg.Done()

	d.logRotator.Start(ctx, &d.wg)
	d.logReaper.Start(ctx, &d.wg)

	ticker := time.NewTicker(constants.DaemonHeartbeatInterval)
	defer ticker.Stop()

	log.Println("Daemon is running...")

	if !proxy.ProxyCAInstalled() {
		log.Println("First time we setup the proxy, uninstall previous setups...")
		if err := d.Uninstall(ctx); err != nil {
			log.Printf("Error uninstalling previous setup (might not exist): %v", err)
		}
	}

	// Start ingress server first (proxy needs its address for callbacks)
	go func() {
		if err := d.ingress.Start(ctx); err != nil {
			log.Printf("Ingress server error: %v", err)
		}
	}()

	// Wait briefly for ingress server to bind
	time.Sleep(100 * time.Millisecond)
	ingressAddr := d.ingress.Addr()
	if ingressAddr == "" {
		return fmt.Errorf("ingress server failed to start")
	}

	if err := d.proxy.Start(ctx, ingressAddr); err != nil {
		return fmt.Errorf("failed to start proxy: %v", err)
	}

	if !proxy.ProxyCAInstalled() {
		if err := proxy.InstallProxyCA(ctx); err != nil {
			return fmt.Errorf("failed to install proxy CA: %v", err)
		}
	}

	if err := setup.Install(ctx); err != nil {
		return fmt.Errorf("failed to install setup: %v", err)
	}

	if err := d.registry.InstallAll(ctx); err != nil {
		return fmt.Errorf("failed to install all scanners: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping daemon loop")
			return nil
		case <-ticker.C:
			if err := d.heartbeat(); err != nil {
				return fmt.Errorf("failed to heartbeat: %v", err)
			}
		}
	}
}

func (d *Daemon) Uninstall(ctx context.Context) error {
	log.Println("Uninstalling the SafeChain Ultimate...")

	if err := d.registry.UninstallAll(ctx); err != nil {
		log.Printf("Error uninstalling scanners: %v", err)
	}

	if err := proxy.UninstallProxyCA(ctx); err != nil {
		return fmt.Errorf("failed to uninstall proxy CA: %v", err)
	}
	return nil
}

func (d *Daemon) heartbeat() error {
	if !proxy.ProxyCAInstalled() {
		log.Println("Proxy CA not installed yet, skipping heartbeat checks...")
		return nil
	}
	if !d.proxy.IsProxyRunning() {
		log.Println("Proxy is not running, starting it...")
	} else {
		log.Println("Proxy is running")
	}
	return nil
}

func (d *Daemon) initLogging() {
	writer, err := platform.SetupLogging()
	if err != nil {
		log.Printf("Failed to setup file logging: %v, using stdout only", err)
	}
	log.SetOutput(writer)
	log.SetFlags(log.LstdFlags)

	d.logRotator.AddLogFile(platform.GetUltimateLogPath(), constants.LogRotationSizeInBytes)
	d.logRotator.AddLogFile(platform.GetUltimateErrLogPath(), constants.LogRotationSizeInBytes)

	d.logReaper.AddLogFile(platform.GetUltimateLogPath(), constants.LogReapingAgeInHours)
	d.logReaper.AddLogFile(platform.GetUltimateErrLogPath(), constants.LogReapingAgeInHours)
	d.logReaper.AddLogFile(platform.GetProxyLogPath(), constants.LogReapingAgeInHours)
	d.logReaper.AddLogFile(platform.GetProxyErrLogPath(), constants.LogReapingAgeInHours)
}
