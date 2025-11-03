package gui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"pistonmaster.net/pistonscan/internal/scanner"
)

// App hosts the web-based graphical interface for PistonScan.
type App struct {
	scanner *scanner.Scanner

	mu            sync.Mutex
	results       []scanner.Result
	expected      int
	currentConfig scanner.Config

	clients map[chan event]struct{}
}

// New constructs a new App instance ready to run.
func New() *App {
	a := &App{
		scanner: scanner.New(),
		clients: make(map[chan event]struct{}),
	}
	a.observeScanner()
	return a
}

// Run starts the HTTP server hosting the GUI and blocks until it stops.
func (a *App) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/start", a.handleStart)
	mux.HandleFunc("/pause", a.handlePause)
	mux.HandleFunc("/resume", a.handleResume)
	mux.HandleFunc("/cancel", a.handleCancel)
	mux.HandleFunc("/export", a.handleExport)
	mux.HandleFunc("/import", a.handleImport)
	mux.HandleFunc("/snapshot", a.handleSnapshot)
	mux.HandleFunc("/events", a.handleEvents)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	fmt.Printf("PistonScan GUI available at http://%s\n", addr)
	a.launchBrowser(addr)

	server := &http.Server{Handler: mux}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, indexHTML)
}

func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Subnet  string `json:"subnet"`
		Threads int    `json:"threads"`
		DelayMS int    `json:"delay_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}
	cfg := scanner.Config{
		Subnet:  strings.TrimSpace(req.Subnet),
		Threads: req.Threads,
		Delay:   time.Duration(req.DelayMS) * time.Millisecond,
		Timeout: 2 * time.Second,
	}
	if err := a.scanner.Start(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	a.results = nil
	a.expected = a.scanner.TargetTotal()
	a.currentConfig = cfg
	a.mu.Unlock()
	a.broadcastSnapshot()
	w.WriteHeader(http.StatusAccepted)
}

func (a *App) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.scanner.Pause()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.scanner.Resume()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.scanner.Cancel()
	a.mu.Lock()
	a.results = a.scanner.Results()
	a.mu.Unlock()
	a.broadcastSnapshot()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	results := append([]scanner.Result(nil), a.results...)
	cfg := a.currentConfig
	a.mu.Unlock()
	if len(results) == 0 {
		http.Error(w, "no scan data to export", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=scan.json")
	if err := scanner.Save(w, cfg, results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (a *App) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "unable to read upload", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	cfg, results, err := scanner.Load(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	a.results = results
	a.expected = len(results)
	a.currentConfig = cfg
	a.mu.Unlock()
	a.broadcastSnapshot()
	w.WriteHeader(http.StatusCreated)
}

func (a *App) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot := a.snapshotEvent()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan event, 8)
	a.addClient(ch)
	defer a.removeClient(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	initial := a.snapshotEvent()
	writeEvent(w, initial)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			writeEvent(w, ev)
			flusher.Flush()
		}
	}
}

func (a *App) observeScanner() {
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
}

func (a *App) broadcastSnapshot() {
	a.broadcast(a.snapshotEvent())
}

func (a *App) snapshotEvent() event {
	a.mu.Lock()
	defer a.mu.Unlock()
	ev := event{
		Type:     "snapshot",
		State:    a.scanner.State().String(),
		Expected: a.expected,
		Results:  make([]ResultPayload, len(a.results)),
	}
	for i, res := range a.results {
		ev.Results[i] = convertResult(res)
	}
	ev.Completed = len(a.results)
	return ev
}

func (a *App) addClient(ch chan event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients[ch] = struct{}{}
}

func (a *App) removeClient(ch chan event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.clients, ch)
	close(ch)
}

func (a *App) broadcast(ev event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for ch := range a.clients {
		select {
		case ch <- ev:
		default:
		}
	}
}

func writeEvent(w http.ResponseWriter, ev event) {
	data, _ := json.Marshal(ev)
	fmt.Fprintf(w, "data: %s\n\n", data)
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

func (a *App) launchBrowser(addr string) {
	url := "http://" + addr
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd != nil {
		cmd.Start()
	}
}

type event struct {
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

// LoadSnapshotFromReader allows tests to supply snapshot data without multipart parsing.
func LoadSnapshotFromReader(r io.Reader) (scanner.Config, []scanner.Result, error) {
	return scanner.Load(r)
}

// SaveSnapshotToWriter exposes snapshot saving for tests or integrations.
func SaveSnapshotToWriter(w io.Writer, cfg scanner.Config, results []scanner.Result) error {
	return scanner.Save(w, cfg, results)
}
