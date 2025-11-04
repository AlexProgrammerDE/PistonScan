package scan

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Manager orchestrates scans and tracks their progress.
type Manager struct {
	mu           sync.Mutex
	config       Config
	status       ScanStatus
	results      map[string]Result
	order        []string
	totalTargets int
	completed    int
	active       int

	scanCtx    context.Context
	scanCancel context.CancelFunc

	pauseMu   sync.Mutex
	pauseCond *sync.Cond
	paused    bool

	updateHandler func(Update)
	statusHandler func(Progress)
}

// NewManager creates a Manager with default values.
func NewManager() *Manager {
	m := &Manager{
		status:  StatusIdle,
		results: make(map[string]Result),
	}
	m.pauseCond = sync.NewCond(&m.pauseMu)
	return m
}

// Start begins a scan with the provided configuration.
func (m *Manager) Start(ctx context.Context, config Config, update func(Update), status func(Progress)) (Snapshot, error) {
	if err := config.Validate(); err != nil {
		return Snapshot{}, err
	}

	targets, err := resolveTargets(config.Subnet)
	if err != nil {
		return Snapshot{}, err
	}
	if len(targets) == 0 {
		return Snapshot{}, errors.New("no targets resolved from subnet")
	}

	m.mu.Lock()
	if m.status == StatusRunning || m.status == StatusPaused {
		snapshot := m.snapshotLocked()
		m.mu.Unlock()
		return snapshot, ErrScanInProgress
	}
	if m.scanCancel != nil {
		m.scanCancel()
		m.scanCancel = nil
	}

	m.scanCtx, m.scanCancel = context.WithCancel(ctx)
	m.config = config
	m.results = make(map[string]Result, len(targets))
	m.order = make([]string, 0, len(targets))
	m.totalTargets = len(targets)
	m.completed = 0
	m.active = 0
	m.paused = false
	m.updateHandler = update
	m.statusHandler = status
	m.status = StatusRunning

	snapshot := m.snapshotLocked()
	m.mu.Unlock()

	m.emitStatus(snapshot.Progress)

	go m.run(m.scanCtx, targets)

	return snapshot, nil
}

// Pause temporarily halts an active scan.
func (m *Manager) Pause() (Progress, error) {
	m.mu.Lock()
	if m.status != StatusRunning {
		progress := m.snapshotLocked().Progress
		m.mu.Unlock()
		return progress, ErrNoActiveScan
	}
	m.pauseMu.Lock()
	m.paused = true
	m.pauseMu.Unlock()
	m.status = StatusPaused
	progress := m.snapshotLocked().Progress
	m.mu.Unlock()

	m.emitStatus(progress)
	return progress, nil
}

// Resume continues a paused scan.
func (m *Manager) Resume() (Progress, error) {
	m.mu.Lock()
	if m.status != StatusPaused {
		progress := m.snapshotLocked().Progress
		m.mu.Unlock()
		return progress, ErrNoActiveScan
	}
	m.pauseMu.Lock()
	m.paused = false
	m.pauseCond.Broadcast()
	m.pauseMu.Unlock()
	m.status = StatusRunning
	progress := m.snapshotLocked().Progress
	m.mu.Unlock()

	m.emitStatus(progress)
	return progress, nil
}

// Cancel stops the active scan entirely.
func (m *Manager) Cancel() (Progress, error) {
	m.mu.Lock()
	if m.status != StatusRunning && m.status != StatusPaused {
		progress := m.snapshotLocked().Progress
		m.mu.Unlock()
		return progress, ErrNoActiveScan
	}
	if m.scanCancel != nil {
		m.scanCancel()
	}
	m.pauseMu.Lock()
	m.paused = false
	m.pauseCond.Broadcast()
	m.pauseMu.Unlock()
	m.status = StatusCancelled
	progress := m.snapshotLocked().Progress
	m.mu.Unlock()

	m.emitStatus(progress)
	return progress, nil
}

// GetSnapshot returns the latest snapshot of the scan state.
func (m *Manager) GetSnapshot() Snapshot {
	m.mu.Lock()
	snapshot := m.snapshotLocked()
	m.mu.Unlock()
	return snapshot
}

// Export serialises the current snapshot to JSON.
func (m *Manager) Export() ([]byte, error) {
	snapshot := m.GetSnapshot()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Import loads scan data from a JSON payload.
func (m *Manager) Import(data []byte) (Snapshot, error) {
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}

	m.mu.Lock()
	if m.scanCancel != nil {
		m.scanCancel()
		m.scanCancel = nil
	}
	m.config = snapshot.Config
	m.results = make(map[string]Result, len(snapshot.Results))
	m.order = make([]string, 0, len(snapshot.Results))
	for _, res := range snapshot.Results {
		m.order = append(m.order, res.IP)
		m.results[res.IP] = res
	}
	total := snapshot.Progress.Total
	if total == 0 {
		total = len(snapshot.Results)
	}
	completed := snapshot.Progress.Completed
	if completed == 0 {
		completed = len(snapshot.Results)
	}
	m.totalTargets = total
	m.completed = completed
	m.active = 0
	m.paused = false
	m.status = StatusCompleted
	snapshot = m.snapshotLocked()
	m.mu.Unlock()

	m.emitStatus(snapshot.Progress)
	return snapshot, nil
}

func (m *Manager) run(ctx context.Context, targets []string) {
	var wg sync.WaitGroup
	limit := m.config.ThreadLimit
	if limit <= 0 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	delay := time.Duration(m.config.DelayMs) * time.Millisecond

Targets:
	for idx, target := range targets {
		select {
		case <-ctx.Done():
			break Targets
		default:
		}

		sem <- struct{}{}
		m.adjustActive(1)
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() {
				<-sem
				m.adjustActive(-1)
			}()
			m.scanTarget(ctx, host)
		}(target)

		if delay > 0 && idx < len(targets)-1 {
			select {
			case <-ctx.Done():
				break Targets
			case <-time.After(delay):
			}
		}
	}

	wg.Wait()

	m.mu.Lock()
	if ctx.Err() == nil && m.status != StatusCancelled {
		m.status = StatusCompleted
	}
	snapshot := m.snapshotLocked()
	m.mu.Unlock()

	m.emitStatus(snapshot.Progress)
}

func (m *Manager) adjustActive(delta int) {
	m.mu.Lock()
	m.active += delta
	snapshot := m.snapshotLocked()
	m.mu.Unlock()
	m.emitStatus(snapshot.Progress)
}

func (m *Manager) scanTarget(ctx context.Context, host string) {
	if err := m.waitWhilePaused(ctx); err != nil {
		return
	}
	if ctx.Err() != nil {
		return
	}

	result := collectHostDetails(ctx, host)
	if ctx.Err() != nil {
		return
	}

	m.mu.Lock()
	if _, exists := m.results[host]; !exists {
		m.order = append(m.order, host)
	}
	m.results[host] = result
	m.completed++
	snapshot := m.snapshotLocked()
	m.mu.Unlock()

	m.emitUpdate(result, snapshot.Progress)
}

func (m *Manager) waitWhilePaused(ctx context.Context) error {
	m.pauseMu.Lock()
	defer m.pauseMu.Unlock()
	for m.paused {
		m.pauseCond.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (m *Manager) emitUpdate(result Result, progress Progress) {
	if handler := m.updateHandler; handler != nil {
		handler(Update{Result: result, Progress: progress})
	}
}

func (m *Manager) emitStatus(progress Progress) {
	if handler := m.statusHandler; handler != nil {
		handler(progress)
	}
}

func (m *Manager) snapshotLocked() Snapshot {
	results := make([]Result, 0, len(m.order))
	for _, key := range m.order {
		if res, ok := m.results[key]; ok {
			results = append(results, res)
		}
	}
	snapshot := Snapshot{
		Config:   m.config,
		Progress: Progress{Total: m.totalTargets, Completed: m.completed, Active: m.active, Status: m.status},
		Results:  results,
		Updated:  time.Now().UTC(),
	}
	return snapshot
}
