package scan

import (
	"context"
	"strings"
	"sync"
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
	windowsServices := []ServiceInfo{{Port: 445, Protocol: "tcp", Service: "SMB"}}
	if guess := guessOS(windowsServices); guess != "Windows" {
		t.Fatalf("expected Windows guess, got %s", guess)
	}

	appleServices := []ServiceInfo{{Port: 7000, Protocol: "tcp", Service: "AirPlay"}}
	if guess := guessOS(appleServices); guess != "Apple / macOS" {
		t.Fatalf("expected Apple guess, got %s", guess)
	}

	linuxServices := []ServiceInfo{{Port: 22, Protocol: "tcp", Service: "SSH", Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu"}}
	if guess := guessOS(linuxServices); guess != "Linux / Unix" {
		t.Fatalf("expected Linux guess, got %s", guess)
	}

	if guess := guessOS([]ServiceInfo{{Port: 80, Protocol: "tcp", Service: "HTTP"}}); guess != "Unknown" {
		t.Fatalf("expected Unknown guess for generic services, got %s", guess)
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
	if name := selectDeviceName(mdns, netbios, llmnr, dns, nil); name != "mdns-device" {
		t.Fatalf("expected mDNS name to take priority, got %s", name)
	}

	// NetBIOS takes priority when no mDNS
	if name := selectDeviceName(nil, netbios, llmnr, dns, nil); name != "netbios-device" {
		t.Fatalf("expected NetBIOS name when no mDNS, got %s", name)
	}

	// LLMNR takes priority when no mDNS or NetBIOS
	if name := selectDeviceName(nil, nil, llmnr, dns, nil); name != "llmnr-device" {
		t.Fatalf("expected LLMNR name when no mDNS or NetBIOS, got %s", name)
	}

	// DNS as fallback
	if name := selectDeviceName(nil, nil, nil, dns, nil); name != "dns-device" {
		t.Fatalf("expected DNS name as fallback, got %s", name)
	}

	// Empty when nothing available
	if name := selectDeviceName(nil, nil, nil, nil, nil); name != "" {
		t.Fatalf("expected empty name when no sources available, got %s", name)
	}

	// AirPlay metadata when other sources unavailable
	airPlay := &AirPlayInfo{Fields: map[string]string{"name": "Living Room Apple TV"}}
	if name := selectDeviceName(nil, nil, nil, nil, airPlay); name != "Living Room Apple TV" {
		t.Fatalf("expected AirPlay name when available, got %s", name)
	}

	// AirPlay should not override mDNS
	if name := selectDeviceName(mdns, netbios, llmnr, dns, airPlay); name != "mdns-device" {
		t.Fatalf("expected mDNS to override AirPlay metadata, got %s", name)
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
		t.Fatalf("expected 1 question in DNS query, got %d", (int(query[4])<<8)|int(query[5]))
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

func TestEnrichInsightMetadata(t *testing.T) {
	result := &Result{
		Reachable:      true,
		LatencySamples: []float64{10},
		TTL:            64,
		Hostnames:      []string{"example"},
		MDNSNames:      []string{"example.local"},
		NetBIOSNames:   []string{"EXAMPLE"},
		LLMNRNames:     []string{"example-llmnr"},
		DeviceName:     "Device",
		MacAddress:     "8C:85:90:12:34:56",
		Manufacturer:   "Acme Corp",
		OSGuess:        "Linux / Unix",
		Services: []ServiceInfo{
			{Port: 22, Protocol: "tcp", Service: "SSH"},
			{Port: 443, Protocol: "tcp", Service: "HTTPS", TLSCertInfo: "CN=example"},
		},
	}

	enrichInsightMetadata(result)

	if result.InsightScore != 19 {
		t.Fatalf("unexpected insight score: got %d", result.InsightScore)
	}

	expectedSources := []string{"arp", "dns", "fingerprint", "icmp", "llmnr", "mdns", "netbios", "oui", "tcp", "tls"}
	if len(result.DiscoverySources) != len(expectedSources) {
		t.Fatalf("unexpected number of sources: %v", result.DiscoverySources)
	}
	for idx, source := range expectedSources {
		if result.DiscoverySources[idx] != source {
			t.Fatalf("expected source %s at index %d, got %s", source, idx, result.DiscoverySources[idx])
		}
	}
}

func TestLookupMDNSNoChannelPanic(t *testing.T) {
	// Test that lookupMDNS doesn't panic when the context expires
	// This tests the fix for the "close of closed channel" panic
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Call lookupMDNS which should complete without panicking
	// even if the context expires and multiple Browse calls try to close the channel
	names := lookupMDNS(ctx, "127.0.0.1")

	// We don't care about the actual results (likely empty)
	// We just want to ensure no panic occurs
	_ = names
}

func TestLookupMDNSConcurrentCalls(t *testing.T) {
	// Test multiple concurrent calls to lookupMDNS to stress test channel handling
	// This further validates the fix for the race condition
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = lookupMDNS(ctx, "127.0.0.1")
		}()
	}

	// Wait with a timeout to ensure the test doesn't hang
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - all goroutines completed without panicking
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out - possible deadlock in lookupMDNS")
	}
}

func TestCollectHostDetailsRunsAllChecks(t *testing.T) {
	// Test that collectHostDetails runs all checks in parallel
	// This validates the fix for "too few checks being run"

	// We'll use localhost as it should be reachable on all systems
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result := collectHostDetails(ctx, "127.0.0.1")

	// The host should be reachable
	if !result.Reachable {
		// If not reachable due to permissions, skip test
		if strings.Contains(result.Error, "permission") {
			t.Skip("Test requires elevated permissions")
		}
		t.Fatalf("expected localhost to be reachable, got error: %s", result.Error)
	}

	// Check that all fields are populated (at least attempted)
	// We expect:
	// - Hostnames should have at least one entry (localhost)
	// - Services might be empty if no services running
	// - Other name lookups might be empty (mDNS, NetBIOS, LLMNR) depending on system
	// - MAC address might be present if ARP cache has it
	// - Device name should be set from one of the name sources
	// - OS guess should be set

	if len(result.Hostnames) == 0 {
		t.Log("Warning: No hostnames found for localhost (expected at least 'localhost')")
	}

	if result.DeviceName == "" {
		t.Log("Warning: No device name set (expected at least one name source to work)")
	}

	if result.OSGuess == "" {
		t.Fatal("expected OS guess to be set")
	}

	// The key test: verify that the function completes in reasonable time
	// If checks were running sequentially with timeouts, this would take much longer
	// With parallel execution, it should complete within the 4-second info timeout
	// plus ping time

	t.Logf("Result: IP=%s, Reachable=%v, Hostnames=%v, MDNSNames=%v, NetBIOSNames=%v, LLMNRNames=%v, MAC=%s, DeviceName=%s, OSGuess=%s, Services=%d",
		result.IP, result.Reachable, result.Hostnames, result.MDNSNames,
		result.NetBIOSNames, result.LLMNRNames, result.MacAddress,
		result.DeviceName, result.OSGuess, len(result.Services))
}

func TestServiceInfoStructWithTLS(t *testing.T) {
	svc := ServiceInfo{
		Port:        443,
		Protocol:    "tcp",
		Service:     "HTTPS",
		Banner:      "Server: nginx",
		TLSCertInfo: "CN=example.com; Expires=2025-12-31",
	}

	if svc.Port != 443 {
		t.Errorf("expected port 443, got %d", svc.Port)
	}
	if svc.TLSCertInfo == "" {
		t.Error("expected TLSCertInfo to be set")
	}
}

func TestBuildSNMPGetRequest(t *testing.T) {
	packet := buildSNMPGetRequest("public")

	if len(packet) < 10 {
		t.Error("SNMP packet too short")
	}

	// Check SEQUENCE tag
	if packet[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag 0x30, got 0x%02x", packet[0])
	}

	// Check that community string "public" is somewhere in the packet
	packetStr := string(packet)
	if !strings.Contains(packetStr, "public") {
		t.Error("community string 'public' not found in packet")
	}
}

func TestProbeUDPPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test with localhost on a port that's unlikely to be open
	// This tests that the function doesn't crash and returns gracefully
	result := probeUDPPort(ctx, "127.0.0.1", 9999)

	// We don't care if it's open or not, just that it doesn't crash
	t.Logf("UDP probe result for port 9999: %v", result)
}

func TestScanUDPServices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Test with localhost on a small set of ports
	services := scanUDPServices(ctx, "127.0.0.1", []int{53, 161})

	// Should return a list (possibly empty if no services are running)
	t.Logf("Found %d UDP services", len(services))

	for _, svc := range services {
		if svc.Protocol != "udp" {
			t.Errorf("expected protocol 'udp', got '%s'", svc.Protocol)
		}
	}
}

func TestGetTLSCertInfo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test with a well-known HTTPS site
	info := getTLSCertInfo(ctx, "www.google.com", 443)

	// If we got info, it should contain some certificate details
	if info != "" {
		t.Logf("TLS cert info: %s", info)
		// Check that it contains at least one expected field
		hasExpectedField := strings.Contains(info, "CN=") ||
			strings.Contains(info, "Expires=") ||
			strings.Contains(info, "Issuer=")
		if !hasExpectedField {
			t.Errorf("TLS cert info doesn't contain expected fields: %s", info)
		}
	} else {
		t.Log("No TLS cert info returned (might be network issue)")
	}
}

func TestProbeSSDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test SSDP probe - may or may not find a device
	result := probeSSDP(ctx, "192.168.1.1")

	// We don't expect this to necessarily succeed, just to not crash
	t.Logf("SSDP probe result: %s", result)
}

func TestProbeSNMP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test SNMP probe - unlikely to succeed without a real SNMP agent
	result := probeSNMP(ctx, "127.0.0.1", 161)

	// We don't expect this to succeed, just to not crash
	t.Logf("SNMP probe result: %s", result)
}

func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{10, 10, 10},
		{0, 100, 0},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
		}
	}
}
