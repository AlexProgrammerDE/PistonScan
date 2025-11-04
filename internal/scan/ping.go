package scan

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	ping "github.com/go-ping/ping"
)

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
