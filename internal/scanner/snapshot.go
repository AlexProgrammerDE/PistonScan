package scanner

import (
	"encoding/json"
	"errors"
	"io"
	"time"
)

const snapshotVersion = 1

// Snapshot represents the serialisable state of a scan.
type Snapshot struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Config      SnapshotConfig `json:"config"`
	Results     []SnapshotItem `json:"results"`
}

// SnapshotConfig holds configuration metadata in exported files.
type SnapshotConfig struct {
	Subnet        string `json:"subnet"`
	Threads       int    `json:"threads"`
	DelayMillis   int    `json:"delay_ms"`
	TimeoutMillis int    `json:"timeout_ms"`
}

// SnapshotItem captures a single scan result for export.
type SnapshotItem struct {
	IP           string    `json:"ip"`
	Reachable    bool      `json:"reachable"`
	LatencyMilli int64     `json:"latency_ms"`
	CheckedAt    time.Time `json:"checked_at"`
	Error        string    `json:"error,omitempty"`
}

// Save writes configuration and results to the writer as a JSON snapshot.
func Save(w io.Writer, cfg Config, results []Result) error {
	snap := Snapshot{
		GeneratedAt: time.Now().UTC(),
		Config: SnapshotConfig{
			Subnet:        cfg.Subnet,
			Threads:       cfg.Threads,
			DelayMillis:   int(cfg.Delay / time.Millisecond),
			TimeoutMillis: int(cfg.Timeout / time.Millisecond),
		},
	}
	for _, res := range results {
		snap.Results = append(snap.Results, SnapshotItem{
			IP:           res.IP,
			Reachable:    res.Reachable,
			LatencyMilli: res.Latency.Milliseconds(),
			CheckedAt:    res.CheckedAt,
			Error:        res.Error,
		})
	}

	payload := struct {
		Version  int      `json:"version"`
		Snapshot Snapshot `json:"snapshot"`
	}{
		Version:  snapshotVersion,
		Snapshot: snap,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

// Load reads a snapshot from the reader and returns the configuration and results it contains.
func Load(r io.Reader) (Config, []Result, error) {
	var payload struct {
		Version  int      `json:"version"`
		Snapshot Snapshot `json:"snapshot"`
	}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&payload); err != nil {
		return Config{}, nil, err
	}
	if payload.Version != snapshotVersion {
		return Config{}, nil, errors.New("unsupported snapshot version")
	}

	cfg := Config{
		Subnet:  payload.Snapshot.Config.Subnet,
		Threads: payload.Snapshot.Config.Threads,
		Delay:   time.Duration(payload.Snapshot.Config.DelayMillis) * time.Millisecond,
		Timeout: time.Duration(payload.Snapshot.Config.TimeoutMillis) * time.Millisecond,
	}

	results := make([]Result, 0, len(payload.Snapshot.Results))
	for _, item := range payload.Snapshot.Results {
		results = append(results, Result{
			IP:        item.IP,
			Reachable: item.Reachable,
			Latency:   time.Duration(item.LatencyMilli) * time.Millisecond,
			CheckedAt: item.CheckedAt,
			Error:     item.Error,
		})
	}
	return cfg, results, nil
}
