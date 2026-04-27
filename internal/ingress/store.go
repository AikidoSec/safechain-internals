package ingress

import (
	"sync"

	"github.com/google/uuid"
)

const maxEvents = 500

// eventStore holds blocked events with thread-safe add/get/list.
type eventStore struct {
	mu     sync.RWMutex
	events []BlockEvent
}

// Add appends the event to the store and returns the saved event.
// When the store exceeds maxEvents the oldest entries are discarded.
func (e *eventStore) Add(ev BlockEvent) BlockEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	blocked := BlockEvent{
		ID:          uuid.New().String(),
		TsMs:        ev.TsMs,
		Artifact:    ev.Artifact,
		BlockReason: ev.BlockReason,
		Status:      "blocked",
		Count:       1,
	}
	// If the user already requested access for this artifact, carry that request status forward
	for i := range e.events {
		if e.events[i].Artifact == ev.Artifact && e.events[i].Status != "blocked" {
			blocked.Status = e.events[i].Status
		}
	}

	e.events = append(e.events, blocked)
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
	return blocked
}

func (e *eventStore) MergeChromeBlockIfDuplicate(ev BlockEvent) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.events {
		if e.events[i].Artifact.PackageName == ev.Artifact.PackageName {
			e.events[i].Count++
			e.events[i].TsMs = ev.TsMs
			return true
		}
	}
	return false
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

// UpdateDisplayName sets the artifact display name on the event with the given id.
// Returns the updated event and true if the event was found.
func (e *eventStore) UpdateDisplayName(id, displayName string) (BlockEvent, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, ev := range e.events {
		if ev.ID == id {
			e.events[i].Artifact.DisplayName = displayName
			return e.events[i], true
		}
	}
	return BlockEvent{}, false
}
