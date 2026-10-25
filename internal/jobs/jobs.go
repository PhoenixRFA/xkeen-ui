// Package jobs runs one long mutating operation at a time in the background.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrBusy = errors.New("another job is running")

type Job struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	State   string    `json:"state"` // running | done | failed
	Output  string    `json:"output"`
	Error   string    `json:"error,omitempty"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitempty"`
}

type Manager struct {
	mu    sync.Mutex
	jobs  map[string]*Job
	order []string
	busy  bool
}

func New() *Manager { return &Manager{jobs: map[string]*Job{}} }

func (m *Manager) Start(name string, fn func(ctx context.Context) (string, error)) (string, error) {
	m.mu.Lock()
	if m.busy {
		m.mu.Unlock()
		return "", ErrBusy
	}
	b := make([]byte, 6)
	rand.Read(b)
	j := &Job{ID: hex.EncodeToString(b), Name: name, State: "running", Started: time.Now()}
	m.jobs[j.ID] = j
	m.order = append(m.order, j.ID)
	if len(m.order) > 20 {
		delete(m.jobs, m.order[0])
		m.order = m.order[1:]
	}
	m.busy = true
	m.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		out, err := fn(ctx)
		m.mu.Lock()
		defer m.mu.Unlock()
		j.Output, j.Ended, j.State = out, time.Now(), "done"
		if err != nil {
			j.State, j.Error = "failed", err.Error()
		}
		m.busy = false
	}()
	return j.ID, nil
}

func (m *Manager) Get(id string) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	return *j, true
}
