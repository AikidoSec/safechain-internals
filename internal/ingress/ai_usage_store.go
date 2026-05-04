package ingress

import (
	"fmt"
	"sync"
)

type aiUsageEventStore struct {
	mu     sync.RWMutex
	events []AiUsageEvent
}

func aiUsageEventID(provider, model string) string {
	return fmt.Sprintf("ai-usage-%s-%s", provider, model)
}

// Add records an observation for the given (provider, model) pair. Repeats
// just refresh the stored timestamp. Returns the stored row and `isNew=true`
// when this was the first observation of that (provider, model).
func (s *aiUsageEventStore) Add(ev AiUsageEvent) (AiUsageEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := aiUsageEventID(ev.Provider, ev.Model)

	for i := range s.events {
		if s.events[i].ID == id {
			s.events[i].TsMs = ev.TsMs
			return s.events[i], false
		}
	}

	stored := AiUsageEvent{
		ID:       id,
		TsMs:     ev.TsMs,
		Provider: ev.Provider,
		Model:    ev.Model,
	}
	s.events = append(s.events, stored)
	return stored, true
}

func (s *aiUsageEventStore) List() []AiUsageEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AiUsageEvent, len(s.events))
	copy(out, s.events)
	return out
}

func (s *Server) AiUsageEvents() []AiUsageEvent {
	return s.aiUsageStore.List()
}
