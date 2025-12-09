package daemon

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/aikido/sc-agent/internal/scannermanager"
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
	registry *scannermanager.Registry
}

func New(config *Config) (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	d := &Daemon{
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
		registry: scannermanager.NewRegistry(),
	}

	d.initLogging()

	return d, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	log.Println("Starting sc-agent daemon...")

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

	log.Println("Daemon main loop stopped")
	d.wg.Wait()

	return nil
}

func (d *Daemon) Stop(ctx context.Context) error {
	var err error
	d.stopOnce.Do(func() {
		log.Println("Stopping daemon...")
		d.cancel()

		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Println("Daemon stopped successfully")
		case <-ctx.Done():
			err = fmt.Errorf("timeout waiting for daemon to stop")
			log.Println("Timeout waiting for daemon to stop")
		}
	})
	return err
}

func (d *Daemon) run(ctx context.Context) {
	defer d.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("Daemon is running...")

	err := d.registry.InstallAll(ctx)
	if err != nil {
		log.Printf("Failed to install all scanners: %v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping daemon loop")
			return
		case <-ticker.C:
			d.doWork()
		}
	}
}

func (d *Daemon) doWork() {
	log.Println("Daemon heartbeat")
}

func (d *Daemon) initLogging() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
