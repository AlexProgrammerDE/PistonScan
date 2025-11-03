package scanner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State represents the lifecycle state of a scan operation.
type State int

const (
	// Idle indicates that the scanner is not running a scan.
	Idle State = iota
	// Running indicates that a scan is actively processing targets.
	Running
	// Paused indicates that the scan is temporarily halted.
	Paused
	// Completed indicates that the scan has finished all targets successfully.
	Completed
	// Cancelled indicates that the scan was aborted before completion.
	Cancelled
)

func (s State) String() string {
	switch s {
	case Idle:
		return "Idle"
	case Running:
		return "Running"
	case Paused:
		return "Paused"
	case Completed:
		return "Completed"
	case Cancelled:
		return "Cancelled"
	default:
		return "Unknown"
	}
}

// Config captures user preferences for a scan run.
type Config struct {
	Subnet  string
	Threads int
	Delay   time.Duration
	Timeout time.Duration
}

// Result represents the outcome of scanning a single IP address.
type Result struct {
	IP        string
	Reachable bool
	Latency   time.Duration
	CheckedAt time.Time
	Error     string
}

// Scanner coordinates scanning operations across workers and exposes their progress.
type Scanner struct {
	mu      sync.RWMutex
	cfg     Config
	state   State
	results map[string]Result
	total   int

	updates chan Result
	stateCh chan State

	pauseMu   sync.Mutex
	pauseCond *sync.Cond
	paused    bool

	cancelFn context.CancelFunc
	waitCh   chan struct{}
}

// New creates a scanner ready to execute scans.
func New() *Scanner {
	s := &Scanner{
		state:   Idle,
		results: make(map[string]Result),
		updates: make(chan Result, 128),
		stateCh: make(chan State, 16),
	}
	s.pauseCond = sync.NewCond(&s.pauseMu)
	return s
}

// Start begins a scan based on the provided configuration.
func (s *Scanner) Start(cfg Config) error {
	if cfg.Subnet == "" {
		return errors.New("subnet must be provided")
	}

	ips, err := expandSubnet(cfg.Subnet)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IPs found for subnet %q", cfg.Subnet)
	}

	if cfg.Threads <= 0 {
		cfg.Threads = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Delay < 0 {
		return errors.New("delay must not be negative")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == Running || s.state == Paused {
		return errors.New("scan already in progress")
	}

	s.cfg = cfg
	s.total = len(ips)
	s.results = make(map[string]Result)
	s.paused = false
	s.waitCh = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFn = cancel

	s.setStateLocked(Running)

	go s.run(ctx, ips)

	return nil
}

// Pause suspends the scan until Resume is called.
func (s *Scanner) Pause() {
	s.mu.Lock()
	if s.state != Running {
		s.mu.Unlock()
		return
	}
	s.setStateLocked(Paused)
	s.mu.Unlock()

	s.pauseMu.Lock()
	s.paused = true
	s.pauseMu.Unlock()
}

// Resume continues a paused scan.
func (s *Scanner) Resume() {
	s.mu.Lock()
	if s.state != Paused {
		s.mu.Unlock()
		return
	}
	s.setStateLocked(Running)
	s.mu.Unlock()

	s.pauseMu.Lock()
	s.paused = false
	s.pauseCond.Broadcast()
	s.pauseMu.Unlock()
}

// Cancel stops an active scan immediately.
func (s *Scanner) Cancel() {
	s.mu.Lock()
	if s.state == Idle || s.state == Completed || s.state == Cancelled {
		s.mu.Unlock()
		return
	}
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.setStateLocked(Cancelled)
	waitCh := s.waitCh
	s.mu.Unlock()

	s.pauseMu.Lock()
	s.paused = false
	s.pauseCond.Broadcast()
	s.pauseMu.Unlock()

	if waitCh != nil {
		<-waitCh
	}
}

// Updates exposes a channel of scan result updates.
func (s *Scanner) Updates() <-chan Result {
	return s.updates
}

// StateChanges exposes a channel of state transitions.
func (s *Scanner) StateChanges() <-chan State {
	return s.stateCh
}

// Results returns the current set of results sorted by IP address.
func (s *Scanner) Results() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Result, 0, len(s.results))
	for _, res := range s.results {
		out = append(out, res)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP < out[j].IP
	})
	return out
}

// CurrentConfig returns the configuration used for the current scan.
func (s *Scanner) CurrentConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// TargetTotal returns the number of targets scheduled for the current scan.
func (s *Scanner) TargetTotal() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total
}

// State returns the scanner's current state.
func (s *Scanner) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Wait blocks until the current scan terminates.
func (s *Scanner) Wait() {
	s.mu.RLock()
	waitCh := s.waitCh
	s.mu.RUnlock()
	if waitCh != nil {
		<-waitCh
	}
}

func (s *Scanner) setStateLocked(state State) {
	s.state = state
	select {
	case s.stateCh <- state:
	default:
	}
}

func (s *Scanner) waitIfPaused(ctx context.Context) bool {
	s.pauseMu.Lock()
	for s.paused {
		s.pauseCond.Wait()
	}
	s.pauseMu.Unlock()

	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}

func (s *Scanner) run(ctx context.Context, ips []string) {
	cfg := s.CurrentConfig()
	jobs := make(chan string)
	workerCount := cfg.Threads
	if workerCount > len(ips) {
		workerCount = len(ips)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if !s.waitIfPaused(ctx) {
					return
				}

				latency, reachable, err := ping(ctx, ip, cfg.Timeout)

				result := Result{
					IP:        ip,
					Reachable: reachable,
					Latency:   latency,
					CheckedAt: time.Now(),
				}
				if err != nil {
					result.Error = err.Error()
				}

				s.mu.Lock()
				s.results[ip] = result
				s.mu.Unlock()

				select {
				case s.updates <- result:
				default:
				}

				if cfg.Delay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(cfg.Delay):
					}
				}

				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()

	wg.Wait()

	s.mu.Lock()
	if s.state != Cancelled {
		s.setStateLocked(Completed)
	}
	waitCh := s.waitCh
	s.mu.Unlock()

	if waitCh != nil {
		close(waitCh)
	}
}

func ping(ctx context.Context, ip string, timeout time.Duration) (time.Duration, bool, error) {
	start := time.Now()
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"-c", "1", ip}
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", strconv.Itoa(int(timeout.Milliseconds())), ip}
	} else {
		secs := int(math.Ceil(timeout.Seconds()))
		if secs < 1 {
			secs = 1
		}
		args = []string{"-c", "1", "-W", strconv.Itoa(secs), ip}
	}

	cmd := exec.CommandContext(pingCtx, "ping", args...)
	output, err := cmd.CombinedOutput()
	latency := time.Since(start)

	if errors.Is(pingCtx.Err(), context.DeadlineExceeded) {
		return latency, false, fmt.Errorf("timeout after %s", timeout)
	}

	if err == nil {
		return latency, true, nil
	}

	// Treat exit errors as an unreachable host rather than a fatal error.
	if _, ok := err.(*exec.ExitError); ok {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = "host unreachable"
		}
		return latency, false, errors.New(msg)
	}

	return latency, false, err
}

func expandSubnet(cidr string) ([]string, error) {
	return expandCIDR(cidr)
}
