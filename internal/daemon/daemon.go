package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/constants"
	"github.com/AikidoSec/safechain-internals/internal/device"
	"github.com/AikidoSec/safechain-internals/internal/ingress"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
	"github.com/AikidoSec/safechain-internals/internal/sbom/npm"
	"github.com/AikidoSec/safechain-internals/internal/sbom/pip"
	"github.com/AikidoSec/safechain-internals/internal/scannermanager"
	"github.com/AikidoSec/safechain-internals/internal/setup"
	"github.com/AikidoSec/safechain-internals/internal/uiconfig"
	"github.com/AikidoSec/safechain-internals/internal/utils"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

type Config struct {
	ConfigPath string
	LogLevel   string
}

// uiProcess holds the tray UI process PID so the daemon can kill it on Stop.
type uiProcess struct {
	mu  sync.Mutex
	pid int
}

func (u *uiProcess) setPID(pid int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.pid = pid
}

// Kill sends SIGKILL (Unix) or TerminateProcess (Windows) to the UI process if it was started.
func (u *uiProcess) Kill() {
	u.mu.Lock()
	pid := u.pid
	u.pid = 0
	u.mu.Unlock()
	if pid <= 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("Failed to find UI process %d: %v", pid, err)
		return
	}
	if err := proc.Kill(); err != nil {
		log.Printf("Failed to kill UI process %d: %v", pid, err)
		return
	}
	log.Printf("Stopped UI tray process (PID %d)", pid)
}

type Daemon struct {
	versionInfo                *version.VersionInfo
	deviceInfo                 *device.DeviceInfo
	config                     *Config
	ctx                        context.Context
	cancel                     context.CancelFunc
	wg                         sync.WaitGroup
	stopOnce                   sync.Once
	proxy                      *proxy.Proxy
	registry                   *scannermanager.Registry
	sbomManager                *sbom.Registry
	ingress                    *ingress.Server
	logRotator                 *utils.LogRotator
	logReaper                  *utils.LogReaper
	uiProcess                  *uiProcess
	proxyRetryCount            int
	proxyLastRetryTime         time.Time
	daemonLastStatusLogTime    time.Time
	proxyStatusSentToTray      bool // last proxy running state sent to tray
	proxyStatusTrayInitialized bool // true after we've sent at least once
	daemonLastSBOMReportTime   time.Time
}

func New(ctx context.Context, cancel context.CancelFunc, config *Config) (*Daemon, error) {
	d := &Daemon{
		versionInfo: version.Info,
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
		proxy:       proxy.New(),
		registry:    scannermanager.NewRegistry(),
		sbomManager: newSBOMRegistry(),
		ingress:     ingress.New(),
		logRotator:  utils.NewLogRotator(),
		logReaper:   utils.NewLogReaper(),
		uiProcess:   &uiProcess{},
	}

	if err := platform.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize platform: %v", err)
	}

	d.deviceInfo = device.NewDeviceInfo()
	if d.deviceInfo == nil {
		return nil, fmt.Errorf("failed to create device info")
	}
	d.initLogging()
	return d, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	log.Print("Starting SafeChain Daemon\n")

	log.Printf("Version info:\n%s\n", d.versionInfo.String())
	log.Printf("Device info:\n%s\n", d.deviceInfo.String())

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
			cancel()
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

		d.uiProcess.Kill()

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

func (d *Daemon) startProxyAndInstallCA(ctx context.Context) error {
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
	return nil
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
		if err := d.Uninstall(ctx, false); err != nil {
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

	// Launch UI tray application once at startup (generates token and passes it to the UI)
	go func() {
		if err := d.launchUI(ctx); err != nil {
			log.Printf("Failed to launch UI: %v", err)
		}
	}()

	if err := d.startProxyAndInstallCA(ctx); err != nil {
		return fmt.Errorf("failed to start proxy and install CA: %v", err)
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

func (d *Daemon) Uninstall(ctx context.Context, removeScanners bool) error {
	log.Println("Uninstalling the SafeChain Ultimate...")

	if removeScanners {
		if err := d.registry.UninstallAll(ctx); err != nil {
			log.Printf("Error uninstalling scanners: %v", err)
		}
	}

	if err := proxy.UninstallProxyCA(ctx); err != nil {
		return fmt.Errorf("failed to uninstall proxy CA: %v", err)
	}
	return nil
}

func (d *Daemon) printDaemonStatus() {
	log.Println("Daemon status:")
	if d.proxy.IsProxyRunning() {
		proxyVersion, _ := d.proxy.Version()
		log.Printf("\t- Proxy: %s", proxyVersion)
	} else {
		log.Println("\t- Proxy: not running!")
	}

	for _, scannerName := range d.registry.List() {
		scanner, err := d.registry.Get(scannerName)
		if err != nil {
			continue
		}
		if scanner.IsInstalled(d.ctx) {
			log.Printf("\t- %s: %s", scannerName, scanner.Version(d.ctx))
		}
	}
}

func (d *Daemon) handleProxy() (shouldRetry bool, err error) {
	if d.proxy.IsProxyRunning() {
		return true, nil
	}

	if d.proxyRetryCount >= constants.ProxyStartMaxRetries {
		// Exit daemon loop if proxy start retry limit is reached
		return false, fmt.Errorf("proxy start retry limit reached (%d attempts), not retrying", d.proxyRetryCount)
	}

	if !d.proxyLastRetryTime.IsZero() && time.Since(d.proxyLastRetryTime) < constants.ProxyStartRetryInterval {
		log.Printf("Proxy is not running, waiting for retry interval (%s) before next attempt", constants.ProxyStartRetryInterval)
		return true, nil
	}

	d.proxyRetryCount++
	d.proxyLastRetryTime = time.Now()
	log.Printf("Proxy is not running, starting it... (attempt %d/%d)", d.proxyRetryCount, constants.ProxyStartMaxRetries)

	if err := d.startProxyAndInstallCA(d.ctx); err != nil {
		log.Printf("Failed to start proxy and install CA: %v", err)
		return true, nil
	}

	if d.proxy.IsProxyRunning() {
		log.Println("Proxy started successfully")
		d.proxyRetryCount = 0
		d.proxyLastRetryTime = time.Time{}
	} else {
		log.Printf("Failed to start proxy, will try again later")
	}
	return true, nil
}

func (d *Daemon) reportSBOM() error {
	sbom := d.sbomManager.CollectAllPackages(d.ctx)

	sbomJSON, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM to JSON: %w", err)
	}

	sbomJSONPath := platform.GetSbomJSONPath()
	if err := os.WriteFile(sbomJSONPath, sbomJSON, 0644); err != nil {
		return fmt.Errorf("failed to write SBOM to file: %w", err)
	}

	log.Printf("SBOM written to %s", sbomJSONPath)
	return nil
}

func (d *Daemon) heartbeat() error {
	shouldRetry, err := d.handleProxy()
	if !shouldRetry {
		return fmt.Errorf("failed to handle proxy: %v", err)
	}
	if err != nil {
		log.Printf("Failed to start proxy: %v", err)
	}

	// Notify tray of proxy status whenever it changes
	running := proxy.IsProxyRunning()
	if !d.proxyStatusTrayInitialized || d.proxyStatusSentToTray != running {
		sendProxyStatusToTray(running)
		d.proxyStatusSentToTray = running
		d.proxyStatusTrayInitialized = true
	}

	runIfIntervalExceeded(&d.daemonLastStatusLogTime, constants.DaemonStatusLogInterval, func() {
		d.printDaemonStatus()
	})
	runIfIntervalExceeded(&d.daemonLastSBOMReportTime, constants.SBOMReportInterval, func() {
		if err := d.reportSBOM(); err != nil {
			log.Printf("Failed to report SBOM: %v", err)
		}
	})
	return nil
}

func (d *Daemon) launchUI(ctx context.Context) error {
	ingressAddr := d.ingress.Addr()
	if ingressAddr == "" {
		return fmt.Errorf("ingress server address not available")
	}

	// Generate token and set it so daemon↔UI requests use the same token
	token := uiconfig.GenerateAndSetToken()
	daemonURL := "http://" + ingressAddr

	cfg := platform.GetConfig()
	binaryPath := filepath.Join(cfg.BinaryDir, platform.SafeChainUIAppName)
	args := []string{
		"--daemon_url", daemonURL,
		"--token", token,
	}

	// Launch UI as current user (non-blocking); save PID so Stop can kill it
	pid, err := platform.StartUIProcessInAuditSessionOfCurrentUser(ctx, binaryPath, args)
	if err != nil {
		log.Printf("Failed to launch UI (will retry): %v", err)
		return nil
	}
	d.uiProcess.setPID(pid)
	log.Println("UI tray application launched")
	return nil
}

func newSBOMRegistry() *sbom.Registry {
	r := sbom.NewRegistry()
	r.Register(npm.New())
	r.Register(pip.New())
	return r
}

func runIfIntervalExceeded(lastRun *time.Time, interval time.Duration, fn func()) {
	if time.Since(*lastRun) >= interval {
		fn()
		*lastRun = time.Now()
	}
}

func (d *Daemon) initLogging() {
	writer, err := platform.SetupLogging()
	if err != nil {
		log.Printf("Failed to setup file logging: %v, using stdout only", err)
	}
	log.SetOutput(writer)
	log.SetFlags(log.LstdFlags)

	rotatableLogs := []string{
		platform.GetUltimateLogPath(),
	}
	for _, path := range rotatableLogs {
		d.logRotator.AddLogFile(path, constants.LogRotationSizeInBytes)
	}

	reapableLogs := []string{
		platform.GetUltimateLogPath(),
		platform.GetProxyLogPath(),
	}
	for _, path := range reapableLogs {
		d.logReaper.AddLogFile(path, constants.LogReapingAgeInHours)
	}
}
