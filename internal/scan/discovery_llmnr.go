package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

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
