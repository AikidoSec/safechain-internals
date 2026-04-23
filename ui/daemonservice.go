package main

import (
	"endpoint-protection-ui/daemon"
	"sync"
)

// DaemonService is a Wails-bound service that exposes daemon API calls to the frontend.
type DaemonService struct {
	mu         sync.RWMutex
	setupSteps []string
}

func (s *DaemonService) SetSetupSteps(steps []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setupSteps = steps
}

func (s *DaemonService) GetSetupSteps() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.setupSteps
}

func (s *DaemonService) ListEvents(limit int) ([]daemon.BlockEvent, error) {
	return daemon.ListEvents(limit)
}

func (s *DaemonService) GetEvent(eventId string) (daemon.BlockEvent, error) {
	return daemon.GetEvent(eventId)
}

func (s *DaemonService) RequestAccess(eventId string) error {
	return daemon.RequestAccess(eventId)
}

func (s *DaemonService) ListTlsEvents(limit int) ([]daemon.TlsTerminationFailedEvent, error) {
	return daemon.ListTlsEvents(limit)
}

func (s *DaemonService) GetTlsEvent(eventId string) (daemon.TlsTerminationFailedEvent, error) {
	return daemon.GetTlsEvent(eventId)
}

func (s *DaemonService) GetVersion() (string, error) {
	return daemon.GetVersion()
}

// InstallProxyCertificate downloads the proxy CA (if needed) and runs the OS trust installation flow.
func (s *DaemonService) InstallProxyCertificate() error {
	return daemon.InstallCertificate()
}

func (s *DaemonService) SetToken(token string) error {
	return daemon.SetToken(token)
}

func (s *DaemonService) InstallExtension() error {
	return daemon.InstallExtension()
}

func (s *DaemonService) AllowVpn() error {
	return daemon.AllowVpn()
}

func (s *DaemonService) StartProxy() error {
	return daemon.StartProxy()
}

func (s *DaemonService) IsExtensionInstalled() (bool, error) {
	return daemon.IsExtensionInstalled()
}

func (s *DaemonService) IsExtensionActivated() (bool, error) {
	return daemon.IsExtensionActivated()
}

func (s *DaemonService) IsVpnAllowed() (bool, error) {
	return daemon.IsVpnAllowed()
}

func (s *DaemonService) OpenExtensionSettings() error {
	return daemon.OpenExtensionSettings()
}

func (s *DaemonService) SetInstallWindowOnTop(onTop bool) {
	if setInstallWindowOnTop != nil {
		setInstallWindowOnTop(onTop)
	}
}

func (s *DaemonService) SetupRestart() error {
	return daemon.SetupRestart()
}

func (s *DaemonService) SetupCheck() (bool, error) {
	return daemon.SetupCheck()
}

func (s *DaemonService) SetupStart() error {
	return daemon.SetupStart()
}

// CloseInstallWindow hides the certificate install window.
func (s *DaemonService) CloseInstallWindow() {
	if closeInstallWindow != nil {
		closeInstallWindow()
	}
}

func (s *DaemonService) CollectLogs() error {
	return daemon.CollectLogs()
}
