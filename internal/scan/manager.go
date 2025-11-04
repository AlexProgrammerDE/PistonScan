package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/endobit/oui"
	ping "github.com/go-ping/ping"
	"github.com/grandcat/zeroconf"
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
	IP             string        `json:"ip"`
	Reachable      bool          `json:"reachable"`
	LatencyMs      float64       `json:"latencyMs"`
	LatencySamples []float64     `json:"latencySamples,omitempty"`
	Attempts       int           `json:"attempts"`
	TTL            int           `json:"ttl,omitempty"`
	Hostnames      []string      `json:"hostnames,omitempty"`
	MDNSNames      []string      `json:"mdnsNames,omitempty"`
	NetBIOSNames   []string      `json:"netbiosNames,omitempty"`
	LLMNRNames     []string      `json:"llmnrNames,omitempty"`
	DeviceName     string        `json:"deviceName,omitempty"`
	MacAddress     string        `json:"macAddress,omitempty"`
	Manufacturer   string        `json:"manufacturer,omitempty"`
	OSGuess        string        `json:"osGuess,omitempty"`
	Services       []ServiceInfo `json:"services,omitempty"`
	Error          string        `json:"error,omitempty"`
}

// ServiceInfo describes an identified network service running on a host.
type ServiceInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Banner   string `json:"banner,omitempty"`
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
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
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

func resolveTargets(subnet string) ([]string, error) {
	if ip := net.ParseIP(subnet); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("only IPv4 addresses are supported: %s", subnet)
		}
		return []string{ipv4.String()}, nil
	}

	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR ranges are supported: %s", subnet)
	}

	var targets []string
	for current := ipv4.Mask(ipNet.Mask); ipNet.Contains(current); incrementIP(current) {
		copyIP := make(net.IP, len(current))
		copy(copyIP, current)
		targets = append(targets, copyIP.String())
	}
	return targets, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func collectHostDetails(ctx context.Context, host string) Result {
	result := Result{IP: host}

	summary, err := pingHost(ctx, host, 3)
	result.Attempts = summary.Attempts
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return result
		}
		result.Error = err.Error()
		return result
	}

	if !summary.Reachable {
		result.Error = "no response"
		return result
	}

	result.Reachable = true
	result.LatencyMs = summary.AvgLatency.Seconds() * 1000
	result.LatencySamples = durationsToMillis(summary.Latencies)
	result.TTL = summary.TTL

	infoCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	hostnames := lookupHostnames(infoCtx, host)
	mdnsNames := lookupMDNS(infoCtx, host)
	netbiosNames := lookupNetBIOS(infoCtx, host)
	llmnrNames := lookupLLMNR(infoCtx, host)
	mac := lookupMACAddress(infoCtx, host)
	manufacturer := lookupManufacturer(mac)
	services := scanServices(infoCtx, host, defaultServicePorts)
	deviceName := selectDeviceName(mdnsNames, netbiosNames, llmnrNames, hostnames)
	osGuess := guessOS(summary.TTL, services)

	result.Hostnames = hostnames
	result.MDNSNames = mdnsNames
	result.NetBIOSNames = netbiosNames
	result.LLMNRNames = llmnrNames
	result.MacAddress = mac
	result.Manufacturer = manufacturer
	result.Services = services
	result.DeviceName = deviceName
	result.OSGuess = osGuess

	return result
}

type pingSummary struct {
	Reachable  bool
	Latencies  []time.Duration
	AvgLatency time.Duration
	Attempts   int
	TTL        int
}

func pingHost(ctx context.Context, host string, attempts int) (pingSummary, error) {
	summary := pingSummary{Attempts: attempts}

	pinger, err := ping.NewPinger(host)
	if err != nil {
		return summary, err
	}

	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	} else {
		pinger.SetPrivileged(false)
	}

	if attempts <= 0 {
		attempts = 1
	}
	pinger.Count = attempts
	pinger.Timeout = time.Duration(attempts) * 2 * time.Second

	statsCh := make(chan *ping.Statistics, 1)
	var latenciesMu sync.Mutex

	pinger.OnRecv = func(pkt *ping.Packet) {
		latenciesMu.Lock()
		summary.Latencies = append(summary.Latencies, pkt.Rtt)
		if pkt.Ttl > 0 {
			summary.TTL = pkt.Ttl
		}
		latenciesMu.Unlock()
	}

	pinger.OnFinish = func(stats *ping.Statistics) {
		statsCh <- stats
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- pinger.Run()
	}()

	var stats *ping.Statistics
	var runErr error
	runCompleted := false

	// Create a timer for additional safety in case stats never arrive after Run completes.
	// We allow extra time beyond the ping timeout to account for OnFinish callback processing.
	statsTimeout := time.NewTimer(pinger.Timeout + 2*time.Second)
	defer statsTimeout.Stop()

	// Wait for both the run to complete and stats to be available
	for stats == nil {
		select {
		case <-ctx.Done():
			pinger.Stop()
			return summary, ctx.Err()
		case runErr = <-errCh:
			runCompleted = true
			if runErr != nil {
				return summary, runErr
			}
			// Run completed successfully, now wait for stats
		case stats = <-statsCh:
			// Stats received
		case <-statsTimeout.C:
			// Timeout waiting for stats after Run completed
			if runCompleted {
				return summary, fmt.Errorf("timeout waiting for ping statistics for host %s after %v", host, pinger.Timeout+2*time.Second)
			}
			return summary, fmt.Errorf("ping timeout for host %s", host)
		}
	}

	if stats == nil {
		return summary, errors.New("no statistics available")
	}
	summary.Attempts = stats.PacketsSent
	if stats.PacketsRecv == 0 {
		return summary, errors.New("no response")
	}

	summary.Reachable = true
	summary.AvgLatency = stats.AvgRtt
	return summary, nil
}

const (
	// NetBIOS protocol constants
	netbiosHeaderSize       = 12
	netbiosQuestionSize     = 38
	netbiosMinResponseSize  = 57 // Header + question + minimum answer header
	netbiosNameEntrySize    = 18
	netbiosNameFieldSize    = 15
	netbiosAnswerHeaderSize = 10
)

var (
	macLinePattern      = regexp.MustCompile(`(?i)([0-9a-f]{2}[:-]){5}([0-9a-f]{2})`)
	whitespacePattern   = regexp.MustCompile(`\s+`)
	defaultServicePorts = []int{80, 443, 8080, 8443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 3000, 4200, 5000, 7000, 22, 445, 3389, 5353, 1900, 21, 23, 25, 110, 143, 139, 135, 548, 631, 554, 5357, 8765, 8888, 53}
	knownServiceNames   = map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		135:  "MS RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		548:  "AFP",
		554:  "RTSP",
		631:  "IPP",
		700:  "EPP",
		7000: "AirPlay",
		8080: "HTTP Alt",
		8443: "HTTPS Alt",
		3389: "RDP",
		4200: "Angular Dev",
		5000: "UPnP/WS",
		5353: "mDNS",
		5357: "Web Services",
		8000: "HTTP Dev",
		8888: "HTTP Alt",
	}
)

func lookupHostnames(ctx context.Context, host string) []string {
	// Use a resolver that prefers the cgo resolver, which reads /etc/hosts
	// and uses the system's DNS configuration
	resolver := &net.Resolver{
		PreferGo: false,
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, host)
	if err != nil {
		// Don't log error, just return nil - DNS reverse lookups often fail
		// in home/small office networks without proper PTR records
		return nil
	}
	return uniqueStrings(names)
}

func lookupMDNS(ctx context.Context, host string) []string {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil
	}

	entries := make(chan *zeroconf.ServiceEntry, 10)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resultsMu := sync.Mutex{}
	results := make(map[string]struct{})

	// Helper to add hostname results
	addHostnameResults := func(entry *zeroconf.ServiceEntry) {
		resultsMu.Lock()
		defer resultsMu.Unlock()
		if entry.Instance != "" {
			results[entry.Instance] = struct{}{}
		}
		if entry.HostName != "" {
			// Clean up hostname (remove trailing dot)
			hostname := strings.TrimSuffix(entry.HostName, ".")
			if hostname != "" {
				results[hostname] = struct{}{}
			}
		}
	}

	// Collect results in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range entries {
			// Check all IPv4 addresses for a match
			for _, ipv4 := range entry.AddrIPv4 {
				if ipv4.String() == host {
					addHostnameResults(entry)
					break
				}
			}
			// Also check IPv6 addresses
			for _, ipv6 := range entry.AddrIPv6 {
				if ipv6.String() == host {
					addHostnameResults(entry)
					break
				}
			}
		}
	}()

	// Browse for all service types to find devices
	// This is a broader search that will find more devices
	// Enhanced list of service types for better device discovery
	serviceTypes := []string{
		"_services._dns-sd._udp", // Service discovery
		"_workstation._tcp",      // Workstations
		"_device-info._tcp",      // Device info
		"_http._tcp",             // HTTP servers
		"_https._tcp",            // HTTPS servers
		"_ssh._tcp",              // SSH servers
		"_smb._tcp",              // SMB/Samba file sharing
		"_afpovertcp._tcp",       // Apple Filing Protocol
		"_ftp._tcp",              // FTP servers
		"_printer._tcp",          // Printers
		"_ipp._tcp",              // Internet Printing Protocol
		"_pdl-datastream._tcp",   // Printer PDL data stream
		"_airplay._tcp",          // AirPlay
		"_raop._tcp",             // Remote Audio Output Protocol (AirPlay audio)
		"_homekit._tcp",          // HomeKit devices
		"_hap._tcp",              // HomeKit Accessory Protocol
		"_companion-link._tcp",   // Apple devices
		"_sleep-proxy._udp",      // Bonjour sleep proxy
		"_rdp._tcp",              // Remote Desktop Protocol
		"_rfb._tcp",              // VNC (Remote Frame Buffer)
		"_telnet._tcp",           // Telnet
		"_nfs._tcp",              // NFS file sharing
		"_webdav._tcp",           // WebDAV
		"_daap._tcp",             // Digital Audio Access Protocol (iTunes)
		"_dpap._tcp",             // Digital Photo Access Protocol
		"_dacp._tcp",             // Digital Audio Control Protocol
		"_googlecast._tcp",       // Google Cast/Chromecast
		"_spotify-connect._tcp",  // Spotify Connect
		"_sonos._tcp",            // Sonos speakers
	}

BrowseLoop:
	for _, serviceType := range serviceTypes {
		select {
		case <-ctx.Done():
			break BrowseLoop
		default:
			// Browse for this service type, ignore errors
			_ = resolver.Browse(ctx, serviceType, "local.", entries)
		}
	}

	// Wait for context to expire
	<-ctx.Done()
	close(entries)
	<-done

	resultsMu.Lock()
	defer resultsMu.Unlock()
	if len(results) == 0 {
		return nil
	}
	out := make([]string, 0, len(results))
	for key := range results {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// lookupNetBIOS queries for NetBIOS names using NBNS (NetBIOS Name Service)
// NetBIOS operates on UDP port 137
func lookupNetBIOS(ctx context.Context, host string) []string {
	// NetBIOS Name Query packet structure:
	// Transaction ID: 2 bytes
	// Flags: 2 bytes (0x0000 for query)
	// Questions: 2 bytes (0x0001)
	// Answer RRs: 2 bytes (0x0000)
	// Authority RRs: 2 bytes (0x0000)
	// Additional RRs: 2 bytes (0x0000)
	// Name: encoded NetBIOS name (34 bytes for "*" wildcard)
	// Type: 2 bytes (0x0021 for NB - NetBIOS general name service)
	// Class: 2 bytes (0x0001 for IN - Internet)

	// Create NetBIOS Name Query for wildcard "*" (node status request)
	query := []byte{
		0x82, 0x28, // Transaction ID
		0x00, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		// Encoded "*" - wildcard query
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x00,
		0x00, 0x21, // Type: NB (NetBIOS general name service)
		0x00, 0x01, // Class: IN
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "137"), 1*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Set deadline for the entire operation
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	conn.SetDeadline(deadline)

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return nil
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil
	}

	// Parse NetBIOS response
	// Response format includes name entries after the header
	// Each name entry is 18 bytes: 15 bytes for name + 1 byte for name type + 2 bytes for flags
	return parseNetBIOSResponse(response[:n])
}

func parseNetBIOSResponse(data []byte) []string {
	// Check minimum response size
	if len(data) < netbiosMinResponseSize {
		return nil
	}

	// Check if it's a response (bit 15 of flags should be 1)
	if data[2]&0x80 == 0 {
		return nil
	}

	// Skip to the answer section
	// Header + Question section
	offset := netbiosHeaderSize + netbiosQuestionSize

	if len(data) < offset+netbiosAnswerHeaderSize {
		return nil
	}

	// Skip name pointer (2 bytes), type (2 bytes), class (2 bytes), TTL (4 bytes)
	offset += netbiosAnswerHeaderSize

	// Read data length (2 bytes)
	if len(data) < offset+2 {
		return nil
	}
	dataLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	// Number of names (1 byte)
	if len(data) < offset+1 {
		return nil
	}
	numNames := int(data[offset])
	offset++

	// Use map for efficient duplicate detection
	nameSet := make(map[string]struct{})

	for i := 0; i < numNames && offset+netbiosNameEntrySize <= len(data); i++ {
		// Extract name (15 bytes)
		nameBytes := data[offset : offset+netbiosNameFieldSize]
		name := strings.TrimSpace(string(nameBytes))

		// Name type (1 byte) - we want unique names (type 0x00) and workstation names (type 0x00, 0x03, 0x20)
		nameType := data[offset+netbiosNameFieldSize]

		// Flags (2 bytes) - bit 15 indicates if name is active
		flags := uint16(data[offset+netbiosNameFieldSize+1])<<8 | uint16(data[offset+netbiosNameFieldSize+2])

		// Only add active unique names (not group names)
		if name != "" && flags&0x8000 != 0 && (nameType == 0x00 || nameType == 0x03 || nameType == 0x20) {
			nameSet[name] = struct{}{}
		}

		offset += netbiosNameEntrySize

		// Don't process more than the reported data length
		if offset-netbiosMinResponseSize >= dataLen {
			break
		}
	}

	if len(nameSet) == 0 {
		return nil
	}

	// Convert map to sorted slice
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// lookupLLMNR queries for names using LLMNR (Link-Local Multicast Name Resolution)
// LLMNR uses IPv4 multicast address 224.0.0.252 on UDP port 5355
func lookupLLMNR(ctx context.Context, host string) []string {
	// Create a reverse lookup query - convert IP to in-addr.arpa format
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil // Only support IPv4 for now
	}

	// Build PTR query for reverse lookup (IP to name)
	// Format: x.x.x.x.in-addr.arpa
	arpaName := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ipv4[3], ipv4[2], ipv4[1], ipv4[0])

	// Build DNS query for LLMNR
	query := buildDNSQuery(arpaName, 12) // Type 12 = PTR

	// LLMNR multicast address
	llmnrAddr := &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.252"),
		Port: 5355,
	}

	// We need to listen on the interface connected to this subnet
	// Use a unicast query to the target host instead of multicast for better results
	targetAddr := &net.UDPAddr{
		IP:   ipv4,
		Port: 5355,
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(1 * time.Second)
	}
	conn.SetDeadline(deadline)

	// Try both multicast and unicast
	_, _ = conn.WriteToUDP(query, llmnrAddr)
	_, _ = conn.WriteToUDP(query, targetAddr)

	// Read responses
	response := make([]byte, 512)
	n, _, err := conn.ReadFromUDP(response)
	if err != nil {
		return nil
	}

	// Parse DNS response
	return parseDNSResponse(response[:n])
}

func buildDNSQuery(name string, queryType uint16) []byte {
	// DNS header
	query := []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}

	// Encode domain name
	labels := strings.Split(name, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // End of name

	// Query type and class
	query = append(query, byte(queryType>>8), byte(queryType&0xFF)) // Type
	query = append(query, 0x00, 0x01)                               // Class: IN

	return query
}

func parseDNSResponse(data []byte) []string {
	if len(data) < 12 {
		return nil
	}

	// Check if it's a response
	if data[2]&0x80 == 0 {
		return nil
	}

	// Get answer count
	answerCount := int(data[6])<<8 | int(data[7])
	if answerCount == 0 {
		return nil
	}

	// Skip header (12 bytes) and question section
	offset := 12

	// Skip question name
	for offset < len(data) && data[offset] != 0 {
		if data[offset]&0xC0 == 0xC0 {
			// Compressed name (pointer)
			offset += 2
			break
		}
		offset += int(data[offset]) + 1
	}
	if offset >= len(data) {
		return nil
	}
	if data[offset-1] != 0 && (data[offset-2]&0xC0) != 0xC0 {
		offset++ // Skip final zero byte if not compressed
	}
	offset += 4 // Skip type and class

	var names []string

	// Parse answers
	for i := 0; i < answerCount && offset < len(data); i++ {
		// Skip name (may be compressed)
		if offset >= len(data) {
			break
		}
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(data) && data[offset] != 0 {
				offset += int(data[offset]) + 1
			}
			offset++ // Skip zero byte
		}

		if offset+10 > len(data) {
			break
		}

		// Get type
		recType := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2

		// Skip class (2 bytes) and TTL (4 bytes)
		offset += 6

		// Get data length
		dataLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+dataLen > len(data) {
			break
		}

		// If PTR record, parse the name
		if recType == 12 {
			name := parseDNSName(data, offset)
			if name != "" {
				// Remove .local or .in-addr.arpa suffix if present
				name = strings.TrimSuffix(name, ".local")
				name = strings.TrimSuffix(name, ".in-addr.arpa")
				name = strings.TrimSuffix(name, ".")
				names = append(names, name)
			}
		}

		offset += dataLen
	}

	if len(names) == 0 {
		return nil
	}
	return uniqueStrings(names)
}

func parseDNSName(data []byte, offset int) string {
	var parts []string
	visited := make(map[int]bool)
	maxJumps := 10
	jumps := 0

	for offset < len(data) && jumps < maxJumps {
		if visited[offset] {
			break
		}
		visited[offset] = true

		length := int(data[offset])
		if length == 0 {
			break
		}

		// Check for compression
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			offset = pointer
			jumps++
			continue
		}

		offset++
		if offset+length > len(data) {
			break
		}

		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, ".")
}

func lookupMACAddress(ctx context.Context, host string) string {
	if mac := lookupMACFromProc(host); mac != "" {
		return mac
	}
	return lookupMACViaARPCommand(ctx, host)
}

func lookupMACFromProc(host string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := whitespacePattern.Split(strings.TrimSpace(line), -1)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == host {
			if mac := normaliseMAC(fields[3]); mac != "" {
				return mac
			}
		}
	}
	return ""
}

func lookupMACViaARPCommand(ctx context.Context, host string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "arp", "-a", host)
	} else {
		cmd = exec.CommandContext(ctx, "arp", "-n", host)
	}
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	match := macLinePattern.FindString(string(output))
	return normaliseMAC(match)
}

func lookupManufacturer(mac string) string {
	if mac == "" {
		return ""
	}
	vendor := oui.Vendor(strings.ToLower(mac))
	if vendor != "" {
		return vendor
	}
	return "Unknown"
}

func selectDeviceName(mdns, netbios, llmnr, hostnames []string) string {
	// Prioritize mDNS names as they are most reliable and user-friendly
	if len(mdns) > 0 {
		return mdns[0]
	}
	// NetBIOS names are common on Windows networks
	if len(netbios) > 0 {
		return netbios[0]
	}
	// LLMNR is also common on Windows
	if len(llmnr) > 0 {
		return llmnr[0]
	}
	// Fall back to DNS hostnames
	if len(hostnames) > 0 {
		return hostnames[0]
	}
	return ""
}

func guessOS(ttl int, services []ServiceInfo) string {
	if ttl == 0 {
		ttl = 64
	}
	switch {
	case ttl <= 64:
		if hasService(services, 548) || hasService(services, 7000) {
			return "Apple / macOS"
		}
		return "Linux / Unix"
	case ttl <= 128:
		if hasService(services, 445) || hasService(services, 3389) {
			return "Windows"
		}
		return "Windows (likely)"
	case ttl >= 200:
		return "Network Appliance"
	default:
		return "Unknown"
	}
}

func hasService(services []ServiceInfo, port int) bool {
	for _, svc := range services {
		if svc.Port == port {
			return true
		}
	}
	return false
}

func scanServices(ctx context.Context, host string, ports []int) []ServiceInfo {
	dialer := &net.Dialer{Timeout: 400 * time.Millisecond}
	var services []ServiceInfo
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return services
		default:
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		banner := readServiceBanner(conn, port)
		_ = conn.Close()

		name := knownServiceNames[port]
		if name == "" {
			name = fmt.Sprintf("TCP %d", port)
		}
		services = append(services, ServiceInfo{Port: port, Protocol: "tcp", Service: name, Banner: banner})
	}
	return services
}

func readServiceBanner(conn net.Conn, port int) string {
	if isHTTPPort(port) {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr().String())
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 443, 8080, 8443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8888:
		return true
	default:
		return false
	}
}

func durationsToMillis(values []time.Duration) []float64 {
	if len(values) == 0 {
		return nil
	}
	out := make([]float64, 0, len(values))
	for _, v := range values {
		out = append(out, v.Seconds()*1000)
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, v := range values {
		normalized := strings.TrimSuffix(v, ".")
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normaliseMAC(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(raw, "-", ":"), ".", ":"))
	match := macLinePattern.FindString(raw)
	if match == "" {
		return ""
	}
	parts := strings.Split(match, ":")
	if len(parts) != 6 {
		return ""
	}
	for i := range parts {
		if len(parts[i]) == 1 {
			parts[i] = "0" + parts[i]
		}
	}
	return strings.Join(parts, ":")
}
