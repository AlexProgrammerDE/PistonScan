package gui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"pistonmaster.net/pistonscan/internal/scanner"
)

// App hosts the Wails-based graphical interface for PistonScan.
type App struct {
	scanner *scanner.Scanner

	mu            sync.Mutex
	results       []scanner.Result
	expected      int
	currentConfig scanner.Config

	ctx      context.Context
	observer sync.Once
}

// New constructs a new App instance ready to run.
func New() *App {
	return &App{
		scanner: scanner.New(),
	}
}

// Run starts the Wails application and blocks until it stops.
func (a *App) Run() error {
	return wails.Run(&options.App{
		Title:  "PistonScan",
		Width:  1024,
		Height: 768,
		Assets: assets,
		OnStartup: func(ctx context.Context) {
			a.startup(ctx)
		},
		Bind: []interface{}{a},
	})
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.observer.Do(func() {
		go func() {
			for range a.scanner.Updates() {
				a.mu.Lock()
				a.results = a.scanner.Results()
				a.mu.Unlock()
				a.broadcastSnapshot()
			}
		}()
		go func() {
			for range a.scanner.StateChanges() {
				a.broadcastSnapshot()
			}
		}()
	})
	a.broadcastSnapshot()
}

// Start begins a scan with the provided configuration.
func (a *App) Start(req StartRequest) error {
	cfg := scanner.Config{
		Subnet:  strings.TrimSpace(req.Subnet),
		Threads: req.Threads,
		Delay:   time.Duration(req.DelayMS) * time.Millisecond,
		Timeout: 2 * time.Second,
	}
	if err := a.scanner.Start(cfg); err != nil {
		return err
	}

	a.mu.Lock()
	a.results = nil
	a.expected = a.scanner.TargetTotal()
	a.currentConfig = cfg
	a.mu.Unlock()
	a.broadcastSnapshot()
	return nil
}

// Pause temporarily halts the current scan.
func (a *App) Pause() {
	a.scanner.Pause()
}

// Resume continues a previously paused scan.
func (a *App) Resume() {
	a.scanner.Resume()
}

// Cancel stops the current scan and finalises results.
func (a *App) Cancel() {
	a.scanner.Cancel()
	a.mu.Lock()
	a.results = a.scanner.Results()
	a.mu.Unlock()
	a.broadcastSnapshot()
}

// Export returns the current scan data as JSON for download.
func (a *App) Export() (string, error) {
	a.mu.Lock()
	results := append([]scanner.Result(nil), a.results...)
	cfg := a.currentConfig
	a.mu.Unlock()

	if len(results) == 0 {
		return "", errors.New("no scan data to export")
	}

	var buf bytes.Buffer
	if err := scanner.Save(&buf, cfg, results); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Import loads scan data from JSON provided by the frontend.
func (a *App) Import(data string) error {
	cfg, results, err := scanner.Load(strings.NewReader(data))
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.results = results
	a.expected = len(results)
	a.currentConfig = cfg
	a.mu.Unlock()
	a.broadcastSnapshot()
	return nil
}

// Snapshot returns the latest snapshot of scan progress.
func (a *App) Snapshot() Snapshot {
	return a.snapshotEvent()
}

func (a *App) broadcastSnapshot() {
	if a.ctx == nil {
		return
	}
	snapshot := a.snapshotEvent()
	runtime.EventsEmit(a.ctx, "snapshot", snapshot)
}

func (a *App) snapshotEvent() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	snapshot := Snapshot{
		Type:     "snapshot",
		State:    a.scanner.State().String(),
		Expected: a.expected,
		Results:  make([]ResultPayload, len(a.results)),
	}
	for i, res := range a.results {
		snapshot.Results[i] = convertResult(res)
	}
	snapshot.Completed = len(a.results)
	return snapshot
}

// Snapshot represents the payload emitted to the frontend.
type Snapshot struct {
	Type      string          `json:"type"`
	State     string          `json:"state"`
	Expected  int             `json:"expected"`
	Completed int             `json:"completed"`
	Results   []ResultPayload `json:"results"`
}

// ResultPayload is sent to the web interface for rendering.
type ResultPayload struct {
	IP        string `json:"ip"`
	Reachable bool   `json:"reachable"`
	LatencyMS int64  `json:"latency_ms"`
	CheckedAt string `json:"checked_at"`
	Error     string `json:"error"`
}

// StartRequest contains the user-provided scan options.
type StartRequest struct {
	Subnet  string `json:"subnet"`
	Threads int    `json:"threads"`
	DelayMS int    `json:"delay_ms"`
}

func convertResult(res scanner.Result) ResultPayload {
	return ResultPayload{
		IP:        res.IP,
		Reachable: res.Reachable,
		LatencyMS: res.Latency.Milliseconds(),
		CheckedAt: res.CheckedAt.Format(time.RFC3339),
		Error:     res.Error,
	}
}

// LoadSnapshotFromReader allows tests to supply snapshot data without multipart parsing.
func LoadSnapshotFromReader(r io.Reader) (scanner.Config, []scanner.Result, error) {
	return scanner.Load(r)
}

// SaveSnapshotToWriter exposes snapshot saving for tests or integrations.
func SaveSnapshotToWriter(w io.Writer, cfg scanner.Config, results []scanner.Result) error {
	return scanner.Save(w, cfg, results)
}
