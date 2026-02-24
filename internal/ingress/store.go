package ingress

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// eventStore holds blocked events with thread-safe add/get/list.
type eventStore struct {
	mu     sync.RWMutex
	events []BlockedEvent
}

// Add converts a BlockEvent to a BlockedEvent, generates a UUID, appends to the store, and returns the saved event.
func (e *eventStore) Add(ev BlockEvent) BlockedEvent {
	blocked := BlockedEvent{
		ID:             uuid.New().String(),
		Ts:             time.Now().Format(time.RFC3339),
		Product:        ev.Artifact.Product,
		PackageName:    ev.Artifact.PackageName,
		PackageVersion: ev.Artifact.PackageVersion,
		BypassEnabled:  true,
	}
	e.mu.Lock()
	e.events = append(e.events, blocked)
	e.mu.Unlock()
	return blocked
}

// Get returns the event with the given id and true, or zero value and false if not found.
func (e *eventStore) Get(id string) (BlockedEvent, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ev := range e.events {
		if ev.ID == id {
			return ev, true
		}
	}
	return BlockedEvent{}, false
}

// List returns a copy of all events.
func (e *eventStore) List() []BlockedEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]BlockedEvent, len(e.events))
	copy(out, e.events)
	return out
}
