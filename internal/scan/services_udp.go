package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SSDP/UPnP constants
	ssdpMulticastAddr = "239.255.255.250:1900"
	ssdpTimeout       = 2 * time.Second
)

var (
	defaultUDPPorts = []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353, 5355}
)

// scanUDPServices probes common UDP ports for service detection
func scanUDPServices(ctx context.Context, host string, ports []int) []ServiceInfo {
	if len(ports) == 0 {
		return nil
	}

	concurrency := min(len(ports), 16)
	sem := make(chan struct{}, concurrency)
	results := make(chan ServiceInfo, len(ports))

	var wg sync.WaitGroup

	for _, port := range ports {
		port := port
		wg.Add(1)

		go func() {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			if !probeUDPPort(ctx, host, port) {
				return
			}

			name := knownServiceNames[port]
			if name == "" {
				name = fmt.Sprintf("UDP %d", port)
			}

			var banner string
			// Try specific protocol probes
			switch port {
			case 161, 162:
				banner = probeSNMP(ctx, host, port)
			case 1900:
				banner = probeSSDP(ctx, host)
			}

			service := ServiceInfo{
				Port:     port,
				Protocol: "udp",
				Service:  name,
				Banner:   banner,
			}

			select {
			case results <- service:
			case <-ctx.Done():
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	services := make([]ServiceInfo, 0, len(ports))
	for svc := range results {
		services = append(services, svc)
	}

	sort.Slice(services, func(i, j int) bool {
		if services[i].Port == services[j].Port {
			return services[i].Protocol < services[j].Protocol
		}
		return services[i].Port < services[j].Port
	})

	return services
}

// probeUDPPort checks if a UDP port is open/responsive
func probeUDPPort(ctx context.Context, host string, port int) bool {
	dialer := &net.Dialer{Timeout: 300 * time.Millisecond}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	readDeadline := time.Now().Add(200 * time.Millisecond)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(readDeadline) {
		readDeadline = deadline
	}
	_ = conn.SetDeadline(readDeadline)

	// Send a probe packet (empty or protocol-specific)
	var probe []byte
	switch port {
	case 53: // DNS
		// Simple DNS query for "."
		probe = []byte{
			0x00, 0x01, // Transaction ID
			0x01, 0x00, // Flags (standard query)
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs
			0x00, 0x00, // Authority RRs
			0x00, 0x00, // Additional RRs
			0x00,       // Root domain
			0x00, 0x01, // Type A
			0x00, 0x01, // Class IN
		}
	default:
		// Generic probe
		probe = []byte{0x00}
	}

	_, _ = conn.Write(probe)

	// Try to read response
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	// Only consider the port open if we received data
	return n > 0
}

// probeSNMP attempts SNMP v1/v2c queries with common community strings
func probeSNMP(ctx context.Context, host string, port int) string {
	communityStrings := []string{"public", "private"}

	for _, community := range communityStrings {
		if ctx.Err() != nil {
			return ""
		}
		if response := trySNMPQuery(ctx, host, port, community); response != "" {
			return response
		}
	}
	return ""
}

// trySNMPQuery sends an SNMP GET request for sysDescr (1.3.6.1.2.1.1.1.0)
func trySNMPQuery(ctx context.Context, host string, port int, community string) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	readDeadline := time.Now().Add(1 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(readDeadline) {
		readDeadline = deadline
	}
	_ = conn.SetDeadline(readDeadline)

	// Build SNMP v2c GET request for sysDescr (simplified)
	// This is a basic implementation - full SNMP encoding is complex
	packet := buildSNMPGetRequest(community)

	_, err = conn.Write(packet)
	if err != nil {
		return ""
	}

	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil || n < 10 {
		return ""
	}

	// Parse basic SNMP response
	if response[0] == 0x30 { // SEQUENCE tag
		return fmt.Sprintf("SNMP (community=%s)", community)
	}

	return ""
}

// buildSNMPGetRequest creates a simple SNMP v2c GET request for sysDescr
func buildSNMPGetRequest(community string) []byte {
	// Simplified SNMP GET request for OID 1.3.6.1.2.1.1.1.0 (sysDescr)
	// In a production system, you'd use a proper SNMP library

	// Request ID
	requestID := []byte{0x02, 0x01, 0x01}

	// Error status (0)
	errorStatus := []byte{0x02, 0x01, 0x00}

	// Error index (0)
	errorIndex := []byte{0x02, 0x01, 0x00}

	// OID 1.3.6.1.2.1.1.1.0
	oid := []byte{
		0x30, 0x0d, // SEQUENCE
		0x06, 0x09, // OID tag and length
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // 1.3.6.1.2.1.1.1.0
		0x05, 0x00, // NULL value
	}

	// Varbind list
	varbindList := append([]byte{0x30, byte(len(oid))}, oid...)

	// PDU
	pduData := append(requestID, errorStatus...)
	pduData = append(pduData, errorIndex...)
	pduData = append(pduData, varbindList...)
	pdu := append([]byte{0xa0, byte(len(pduData))}, pduData...)

	// Community string
	communityBytes := []byte(community)
	communityField := append([]byte{0x04, byte(len(communityBytes))}, communityBytes...)

	// Version (v2c = 1)
	version := []byte{0x02, 0x01, 0x01}

	// Build complete message
	message := append(version, communityField...)
	message = append(message, pdu...)

	// Wrap in SEQUENCE
	packet := append([]byte{0x30, byte(len(message))}, message...)

	return packet
}

// probeSSDP performs SSDP/UPnP discovery using M-SEARCH
func probeSSDP(ctx context.Context, host string) string {
	// SSDP M-SEARCH request
	searchMsg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	addr := net.JoinHostPort(host, "1900")
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	readDeadline := time.Now().Add(1 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(readDeadline) {
		readDeadline = deadline
	}
	_ = conn.SetDeadline(readDeadline)

	_, err = conn.Write([]byte(searchMsg))
	if err != nil {
		return ""
	}

	response := make([]byte, 2048)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return ""
	}

	responseStr := string(response[:n])

	// Extract device info from response
	if strings.Contains(responseStr, "HTTP/1.1 200 OK") ||
		strings.Contains(responseStr, "SERVER:") ||
		strings.Contains(responseStr, "LOCATION:") {
		// Parse server or device type
		lines := strings.Split(responseStr, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return "UPnP: " + strings.TrimSpace(parts[1])
				}
			}
		}
		return "UPnP Device"
	}

	return ""
}
