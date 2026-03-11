package ingress

import (
	"sync"

	"github.com/google/uuid"
)

// eventStore holds blocked events with thread-safe add/get/list.
type eventStore struct {
	mu     sync.RWMutex
	events []BlockEvent
}

// Add appends the event to the store and returns the saved event.
func (e *eventStore) Add(ev BlockEvent) BlockEvent {
	blocked := BlockEvent{
		ID:          uuid.New().String(),
		TsMs:        ev.TsMs,
		Artifact:    ev.Artifact,
		BlockReason: ev.BlockReason,
		Status:      "blocked",
	}
	e.mu.Lock()
	e.events = append(e.events, blocked)
	e.mu.Unlock()
	return blocked
}

// Get returns the event with the given id and true, or zero value and false if not found.
func (e *eventStore) Get(id string) (BlockEvent, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ev := range e.events {
		if ev.ID == id {
			return ev, true
		}
	}
	return BlockEvent{}, false
}

// List returns a copy of all events.
func (e *eventStore) List() []BlockEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]BlockEvent, len(e.events))
	copy(out, e.events)
	return out
}

// UpdateStatus sets the status field on the event with the given id.
// Returns true if the event was found.
func (e *eventStore) UpdateStatus(id, status string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, ev := range e.events {
		if ev.ID == id {
			e.events[i].Status = status
			return true
		}
	}
	return false
}
