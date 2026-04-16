package ingress

import (
	"sync"

	"github.com/google/uuid"
)

type tlsEventStore struct {
	mu     sync.RWMutex
	events []TlsTerminationFailedEvent
}

func (e *tlsEventStore) Add(ev TlsTerminationFailedEvent) TlsTerminationFailedEvent {
	stored := TlsTerminationFailedEvent{
		ID:      uuid.New().String(),
		TsMs:    ev.TsMs,
		SNI:     ev.SNI,
		App:     ev.App,
		AppPath: ev.AppPath,
		Error:   ev.Error,
	}
	e.mu.Lock()
	e.events = append(e.events, stored)
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
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
