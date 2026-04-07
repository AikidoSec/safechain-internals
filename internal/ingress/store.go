package ingress

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/google/uuid"
)

const maxEvents = 500

// eventStore holds blocked events with thread-safe add/get/list.
type eventStore struct {
	mu     sync.RWMutex
	path   string
	events []BlockEvent
}

func newEventStore(path string) *eventStore {
	e := &eventStore{path: path}
	if err := e.loadFromDisk(); err != nil {
		log.Printf("ingress: failed to load block events from %s: %v", path, err)
	}
	return e
}

func (e *eventStore) loadFromDisk() error {
	if e.path == "" {
		return nil
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var events []BlockEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return err
	}
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}
	e.mu.Lock()
	e.events = events
	e.mu.Unlock()
	return nil
}

func (e *eventStore) persistLocked() {
	if e.path == "" {
		return
	}
	data, err := json.MarshalIndent(e.events, "", "  ")
	if err != nil {
		log.Printf("ingress: failed to marshal block events: %v", err)
		return
	}
	if err := os.WriteFile(e.path, data, 0600); err != nil {
		log.Printf("ingress: failed to write block events: %v", err)
	}
}

// Add appends the event to the store and returns the saved event.
// When the store exceeds maxEvents the oldest entries are discarded.
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
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
	e.persistLocked()
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
			e.persistLocked()
			return true
		}
	}
	return false
}
