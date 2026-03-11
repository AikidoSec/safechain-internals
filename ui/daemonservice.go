package main

import (
	"changeme/daemon"
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
