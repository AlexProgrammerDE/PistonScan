package scan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestResolveTargetsSingleIP(t *testing.T) {
	targets, err := resolveTargets("192.168.1.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0] != "192.168.1.10" {
		t.Fatalf("expected target to equal input IP, got %s", targets[0])
	}
}

func TestResolveTargetsCIDR(t *testing.T) {
	targets, err := resolveTargets("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("expected 4 targets, got %d", len(targets))
	}
	expected := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, target := range targets {
		if target != expected[i] {
			t.Fatalf("target %d: expected %s, got %s", i, expected[i], target)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := Config{Subnet: "192.168.1.0/30", ThreadLimit: 2, DelayMs: 0}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	bad := []Config{
		{Subnet: "", ThreadLimit: 1, DelayMs: 0},
		{Subnet: "192.168.1.0/30", ThreadLimit: 0, DelayMs: 0},
		{Subnet: "192.168.1.0/30", ThreadLimit: 1, DelayMs: -1},
	}
	for idx, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("expected validation error for config %d", idx)
		}
	}
}

func TestDurationsToMillis(t *testing.T) {
	values := []time.Duration{500 * time.Microsecond, 2 * time.Millisecond, 1500 * time.Millisecond}
	got := durationsToMillis(values)
	if len(got) != 3 {
		t.Fatalf("expected 3 values, got %d", len(got))
	}
	if got[0] <= 0 || got[1] <= got[0] {
		t.Fatalf("expected ascending millisecond values, got %v", got)
	}
}

func TestNormaliseMAC(t *testing.T) {
	input := "8c-85-90-12-34-56"
	want := "8C:85:90:12:34:56"
	if got := normaliseMAC(input); got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
	if normaliseMAC("invalid") != "" {
		t.Fatalf("expected empty result for invalid mac")
	}
}

func TestGuessOS(t *testing.T) {
	services := []ServiceInfo{{Port: 445, Protocol: "tcp", Service: "SMB"}}
	if guess := guessOS(120, services); !strings.Contains(guess, "Windows") {
		t.Fatalf("expected Windows guess, got %s", guess)
	}
	if guess := guessOS(40, []ServiceInfo{{Port: 7000, Protocol: "tcp", Service: "AirPlay"}}); !strings.Contains(guess, "Apple") {
		t.Fatalf("expected Apple guess, got %s", guess)
	}
	if guess := guessOS(220, nil); guess != "Network Appliance" {
		t.Fatalf("expected network appliance, got %s", guess)
	}
}

func TestPingHostLocalhost(t *testing.T) {
	// Test pinging localhost which should work on all platforms
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	summary, err := pingHost(ctx, "127.0.0.1", 3)

	if err != nil {
		// On some systems without proper permissions, this might fail
		if strings.Contains(err.Error(), "permission denied") {
			t.Skip("Test requires elevated permissions")
		}
		t.Fatalf("unexpected error pinging localhost: %v", err)
	}

	if !summary.Reachable {
		t.Fatalf("expected localhost to be reachable")
	}

	if summary.Attempts == 0 {
		t.Fatalf("expected non-zero attempts")
	}

	if len(summary.Latencies) == 0 {
		t.Fatalf("expected some latency measurements, got none")
	}

	if summary.AvgLatency == 0 {
		t.Fatalf("expected non-zero average latency")
	}
}

func TestLookupHostnames(t *testing.T) {
	// Test hostname lookup for localhost
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hostnames := lookupHostnames(ctx, "127.0.0.1")

	// localhost should resolve to "localhost" or similar
	if len(hostnames) == 0 {
		t.Fatalf("expected at least one hostname for 127.0.0.1, got none")
	}

	// Check if "localhost" is in the results
	found := false
	for _, name := range hostnames {
		if strings.Contains(strings.ToLower(name), "localhost") {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected 'localhost' in hostnames, got %v", hostnames)
	}
}

func TestUniqueStrings(t *testing.T) {
	input := []string{"host1.local.", "host2.local.", "host1.local.", "host3.local."}
	result := uniqueStrings(input)

	if len(result) != 3 {
		t.Fatalf("expected 3 unique strings, got %d: %v", len(result), result)
	}

	// Check that trailing dots are removed
	for _, s := range result {
		if strings.HasSuffix(s, ".") {
			t.Fatalf("expected no trailing dots, got %s", s)
		}
	}

	// Check that results are sorted
	for i := 1; i < len(result); i++ {
		if result[i-1] >= result[i] {
			t.Fatalf("expected sorted results, got %v", result)
		}
	}
}

func TestSelectDeviceName(t *testing.T) {
	// Test priority order: mDNS > NetBIOS > LLMNR > DNS
	mdns := []string{"mdns-device"}
	netbios := []string{"netbios-device"}
	llmnr := []string{"llmnr-device"}
	dns := []string{"dns-device"}

	// mDNS takes priority
	if name := selectDeviceName(mdns, netbios, llmnr, dns); name != "mdns-device" {
		t.Fatalf("expected mDNS name to take priority, got %s", name)
	}

	// NetBIOS takes priority when no mDNS
	if name := selectDeviceName(nil, netbios, llmnr, dns); name != "netbios-device" {
		t.Fatalf("expected NetBIOS name when no mDNS, got %s", name)
	}

	// LLMNR takes priority when no mDNS or NetBIOS
	if name := selectDeviceName(nil, nil, llmnr, dns); name != "llmnr-device" {
		t.Fatalf("expected LLMNR name when no mDNS or NetBIOS, got %s", name)
	}

	// DNS as fallback
	if name := selectDeviceName(nil, nil, nil, dns); name != "dns-device" {
		t.Fatalf("expected DNS name as fallback, got %s", name)
	}

	// Empty when nothing available
	if name := selectDeviceName(nil, nil, nil, nil); name != "" {
		t.Fatalf("expected empty name when no sources available, got %s", name)
	}
}

func TestBuildDNSQuery(t *testing.T) {
	query := buildDNSQuery("test.local", 12) // PTR query

	// Check that query is not empty and has minimum length
	if len(query) < 12 {
		t.Fatalf("expected DNS query to have at least 12 bytes (header), got %d", len(query))
	}

	// Check header structure
	// Questions count should be 1
	if query[4] != 0x00 || query[5] != 0x01 {
		t.Fatalf("expected 1 question in DNS query, got %d", int(query[4])<<8|int(query[5]))
	}

	// Check that it ends with query type (12 = PTR) and class (1 = IN)
	queryLen := len(query)
	if queryLen >= 4 {
		queryType := uint16(query[queryLen-4])<<8 | uint16(query[queryLen-3])
		if queryType != 12 {
			t.Fatalf("expected query type 12 (PTR), got %d", queryType)
		}
	}
}

func TestParseDNSName(t *testing.T) {
	// Test simple domain name parsing
	// Format: length + label + length + label + ... + 0x00
	data := []byte{
		0x04, 't', 'e', 's', 't', // "test"
		0x05, 'l', 'o', 'c', 'a', 'l', // "local"
		0x00, // end
	}

	name := parseDNSName(data, 0)
	expected := "test.local"

	if name != expected {
		t.Fatalf("expected %s, got %s", expected, name)
	}
}

func TestParseNetBIOSResponse(t *testing.T) {
	// Test with an empty response
	names := parseNetBIOSResponse([]byte{})
	if names != nil {
		t.Fatalf("expected nil for empty response, got %v", names)
	}

	// Test with response too short
	shortData := make([]byte, 50)
	names = parseNetBIOSResponse(shortData)
	if names != nil {
		t.Fatalf("expected nil for short response, got %v", names)
	}
}

func TestParseDNSResponse(t *testing.T) {
	// Test with an empty response
	names := parseDNSResponse([]byte{})
	if names != nil {
		t.Fatalf("expected nil for empty response, got %v", names)
	}

	// Test with response too short
	shortData := make([]byte, 10)
	names = parseDNSResponse(shortData)
	if names != nil {
		t.Fatalf("expected nil for short response, got %v", names)
	}

	// Test with valid header but no answers
	noAnswers := []byte{
		0x00, 0x01, // Transaction ID
		0x80, 0x00, // Flags: response
		0x00, 0x00, // Questions: 0
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}
	names = parseDNSResponse(noAnswers)
	if names != nil {
		t.Fatalf("expected nil for response with no answers, got %v", names)
	}
}

func TestResultStructWithNewFields(t *testing.T) {
	// Test that Result struct properly handles new fields
	result := Result{
		IP:           "192.168.1.100",
		Reachable:    true,
		Hostnames:    []string{"host.local"},
		MDNSNames:    []string{"mdns-host"},
		NetBIOSNames: []string{"NETBIOS-HOST"},
		LLMNRNames:   []string{"llmnr-host"},
	}

	if len(result.NetBIOSNames) != 1 || result.NetBIOSNames[0] != "NETBIOS-HOST" {
		t.Fatalf("expected NetBIOS name to be set correctly")
	}

	if len(result.LLMNRNames) != 1 || result.LLMNRNames[0] != "llmnr-host" {
		t.Fatalf("expected LLMNR name to be set correctly")
	}
}

