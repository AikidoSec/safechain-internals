package ingress

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/google/uuid"
)

type tlsEventStore struct {
	mu     sync.RWMutex
	path   string
	events []TlsTerminationFailedEvent
}

func newTlsEventStore(path string) *tlsEventStore {
	e := &tlsEventStore{path: path}
	if err := e.loadFromDisk(); err != nil {
		log.Printf("ingress: failed to load TLS events from %s: %v", path, err)
	}
	return e
}

func (e *tlsEventStore) loadFromDisk() error {
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
	var events []TlsTerminationFailedEvent
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

func (e *tlsEventStore) persistLocked() {
	if e.path == "" {
		return
	}
	data, err := json.MarshalIndent(e.events, "", "  ")
	if err != nil {
		log.Printf("ingress: failed to marshal TLS events: %v", err)
		return
	}
	if err := os.WriteFile(e.path, data, 0600); err != nil {
		log.Printf("ingress: failed to write TLS events: %v", err)
	}
}

func (e *tlsEventStore) Add(ev TlsTerminationFailedEvent) TlsTerminationFailedEvent {
	stored := TlsTerminationFailedEvent{
		ID:    uuid.New().String(),
		TsMs:  ev.TsMs,
		SNI:   ev.SNI,
		App:   ev.App,
		Error: ev.Error,
	}
	e.mu.Lock()
	e.events = append(e.events, stored)
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
	e.persistLocked()
	e.mu.Unlock()
	return stored
}

func (e *tlsEventStore) Get(id string) (TlsTerminationFailedEvent, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ev := range e.events {
		if ev.ID == id {
			return ev, true
		}
	}
	return TlsTerminationFailedEvent{}, false
}

func (e *tlsEventStore) List() []TlsTerminationFailedEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TlsTerminationFailedEvent, len(e.events))
	copy(out, e.events)
	return out
}
