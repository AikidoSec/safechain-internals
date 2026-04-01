package main

import (
	"endpoint-protection-ui/daemon"
)

// DaemonService is a Wails-bound service that exposes daemon API calls to the frontend.
type DaemonService struct{}

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
