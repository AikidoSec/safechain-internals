package daemon

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Config holds the daemon configuration
type Config struct {
	ConfigPath string
	LogLevel   string
}

// Daemon represents the main daemon instance
type Daemon struct {
	config   *Config
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopOnce sync.Once
	running  bool
	mu       sync.RWMutex
}

// New creates a new daemon instance
func New(config *Config) (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	d := &Daemon{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize logging
	if err := d.initLogging(); err != nil {
		return nil, fmt.Errorf("failed to initialize logging: %w", err)
	}

	return d, nil
}

// Start starts the daemon
func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("daemon is already running")
	}
	d.running = true
	d.mu.Unlock()

	log.Println("Starting safechain-agent daemon...")

	// Merge contexts
	mergedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Cancel merged context when daemon context is cancelled
	go func() {
		select {
		case <-d.ctx.Done():
			cancel()
		case <-mergedCtx.Done():
		}
	}()

	// Start main daemon loop
	d.wg.Add(1)
	go d.run(mergedCtx)

	// Wait for context cancellation
	<-mergedCtx.Done()

	d.mu.Lock()
	d.running = false
	d.mu.Unlock()

	log.Println("Daemon main loop stopped")
	d.wg.Wait()

	return nil
}

// Stop stops the daemon gracefully
func (d *Daemon) Stop(ctx context.Context) error {
	var err error
	d.stopOnce.Do(func() {
		log.Println("Stopping daemon...")
		d.cancel()

		// Wait for goroutines to finish or context timeout
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

// run is the main daemon loop
func (d *Daemon) run(ctx context.Context) {
	defer d.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("Daemon is running...")

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping daemon loop")
			return
		case <-ticker.C:
			// Main daemon work goes here
			d.doWork()
		}
	}
}

// doWork performs the daemon's periodic work
func (d *Daemon) doWork() {
	// This is where your daemon's main logic goes
	// For now, just a placeholder
	log.Println("Daemon heartbeat")
}

// initLogging initializes the logging system
func (d *Daemon) initLogging() error {
	// Configure logging based on log level
	// For now, using standard log package
	// You can replace this with a more sophisticated logger
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	return nil
}

// IsRunning returns whether the daemon is currently running
func (d *Daemon) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}
