package ingress

import (
	"fmt"
	"sync"
)

type minPackageAgeEventStore struct {
	mu     sync.RWMutex
	events []MinPackageAgeEvent
}

const minPackageAgeEventID = "min-package-age-suppressed"

func (e *minPackageAgeEventStore) Add(ev MinPackageAgeEvent) MinPackageAgeEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	ecosystem := ev.Ecosystem
	if ecosystem == "" {
		ecosystem = ev.Artifact.Product
	}
	if ecosystem == "" {
		ecosystem = "unknown"
	}

	stableID := fmt.Sprintf("min-package-age-suppressed-%s", ecosystem)
	title := fmt.Sprintf("%s package versions suppressed", ecosystem)

	for i := range e.events {
		if e.events[i].ID == stableID {
			e.events[i].TsMs = ev.TsMs
			return e.events[i]
		}
	}

	stored := MinPackageAgeEvent{
		ID:        stableID,
		TsMs:      ev.TsMs,
		Ecosystem: ecosystem,
		Title:     title,
		Message:   "One or more package versions were suppressed because they did not meet the minimum package age policy. Please consult app.aikido.dev for SBOM details.",
	}

	e.events = append(e.events, stored)

	return stored
}

func (e *minPackageAgeEventStore) Get(id string) (MinPackageAgeEvent, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ev := range e.events {
		if ev.ID == id {
			return ev, true
		}
	}
	return MinPackageAgeEvent{}, false
}

func (e *minPackageAgeEventStore) List() []MinPackageAgeEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]MinPackageAgeEvent, len(e.events))
	copy(out, e.events)
	return out
}
