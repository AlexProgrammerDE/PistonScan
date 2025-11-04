package main

import (
	"context"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"pistonscan/internal/scan"
)

// App struct
type App struct {
	ctx     context.Context
	manager *scan.Manager
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{manager: scan.NewManager()}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) handleUpdate(update scan.Update) {
	runtime.EventsEmit(a.ctx, "scan:update", update)
}

func (a *App) handleStatus(progress scan.Progress) {
	runtime.EventsEmit(a.ctx, "scan:status", progress)
}

// StartScan initialises a new scan with the provided configuration.
func (a *App) StartScan(config scan.Config) (scan.Snapshot, error) {
	return a.manager.Start(a.ctx, config, a.handleUpdate, a.handleStatus)
}

// PauseScan halts the active scan.
func (a *App) PauseScan() (scan.Progress, error) {
	return a.manager.Pause()
}

// ResumeScan continues a paused scan.
func (a *App) ResumeScan() (scan.Progress, error) {
	return a.manager.Resume()
}

// CancelScan terminates the active scan.
func (a *App) CancelScan() (scan.Progress, error) {
	return a.manager.Cancel()
}

// GetSnapshot returns the latest scan snapshot.
func (a *App) GetSnapshot() scan.Snapshot {
	return a.manager.GetSnapshot()
}

// ExportResults exports the current scan snapshot to JSON.
func (a *App) ExportResults() (string, error) {
	data, err := a.manager.Export()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ImportResults loads scan data from JSON.
func (a *App) ImportResults(payload string) (scan.Snapshot, error) {
	return a.manager.Import([]byte(payload))
}
