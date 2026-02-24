package main

import (
	"changeme/daemon"
)

type DaemonService struct{}

// ListEvents returns GET /v1/events with the given limit (default 50).
func (s *DaemonService) ListEvents(limit int) ([]daemon.BlockedEvent, error) {
	return daemon.ListEvents(limit)
}

// GetEvent returns GET /v1/events/:id.
func (s *DaemonService) GetEvent(eventId string) (daemon.BlockedEvent, error) {
	return daemon.GetEvent(eventId)
}

// RequestAccess sends POST /v1/events/:id/request-access.
func (s *DaemonService) RequestAccess(eventId string, message string) error {
	return daemon.RequestAccess(eventId, message)
}
