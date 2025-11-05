package scan

import (
	"errors"
	"time"
)

// Config describes the parameters of a scan run.
type Config struct {
	Subnet      string `json:"subnet"`
	ThreadLimit int    `json:"threadLimit"`
	DelayMs     int    `json:"delayMs"`
}

// Validate checks that the configuration is usable.
func (c Config) Validate() error {
	if c.Subnet == "" {
		return errors.New("subnet is required")
	}
	if c.ThreadLimit <= 0 {
		return errors.New("threadLimit must be greater than 0")
	}
	if c.DelayMs < 0 {
		return errors.New("delayMs cannot be negative")
	}
	return nil
}

// ScanStatus represents the lifecycle state of a scan.
type ScanStatus string

const (
	StatusIdle      ScanStatus = "idle"
	StatusRunning   ScanStatus = "running"
	StatusPaused    ScanStatus = "paused"
	StatusCancelled ScanStatus = "cancelled"
	StatusCompleted ScanStatus = "completed"
)

// Result captures information gathered for a single host.
type Result struct {
	IP               string        `json:"ip"`
	Reachable        bool          `json:"reachable"`
	LatencyMs        float64       `json:"latencyMs"`
	LatencySamples   []float64     `json:"latencySamples,omitempty"`
	Attempts         int           `json:"attempts"`
	TTL              int           `json:"ttl,omitempty"`
	Hostnames        []string      `json:"hostnames,omitempty"`
	MDNSNames        []string      `json:"mdnsNames,omitempty"`
	NetBIOSNames     []string      `json:"netbiosNames,omitempty"`
	LLMNRNames       []string      `json:"llmnrNames,omitempty"`
	DeviceName       string        `json:"deviceName,omitempty"`
	MacAddress       string        `json:"macAddress,omitempty"`
	Manufacturer     string        `json:"manufacturer,omitempty"`
	OSGuess          string        `json:"osGuess,omitempty"`
	Services         []ServiceInfo `json:"services,omitempty"`
	AirPlay          *AirPlayInfo  `json:"airPlay,omitempty"`
	DiscoverySources []string      `json:"discoverySources,omitempty"`
	InsightScore     int           `json:"insightScore,omitempty"`
	Error            string        `json:"error,omitempty"`
}

// ServiceInfo describes an identified network service running on a host.
type ServiceInfo struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Service     string `json:"service"`
	Banner      string `json:"banner,omitempty"`
	TLSCertInfo string `json:"tlsCertInfo,omitempty"`
}

// AirPlayInfo captures additional metadata advertised by AirPlay devices.
type AirPlayInfo struct {
	Endpoint string            `json:"endpoint,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// Progress contains a summary of the current scan progress.
type Progress struct {
	Total     int        `json:"total"`
	Completed int        `json:"completed"`
	Active    int        `json:"active"`
	Status    ScanStatus `json:"status"`
}

// Snapshot is a point-in-time view of a scan's configuration, results and progress.
type Snapshot struct {
	Config   Config    `json:"config"`
	Progress Progress  `json:"progress"`
	Results  []Result  `json:"results"`
	Updated  time.Time `json:"updated"`
}

// Update represents an incremental scan result.
type Update struct {
	Result   Result   `json:"result"`
	Progress Progress `json:"progress"`
}

var (
	// ErrScanInProgress indicates a scan is already running.
	ErrScanInProgress = errors.New("scan already in progress")
	// ErrNoActiveScan indicates there is no running or paused scan to control.
	ErrNoActiveScan = errors.New("no active scan")
)
