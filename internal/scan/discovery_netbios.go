package scan

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	// NetBIOS protocol constants
	netbiosHeaderSize       = 12
	netbiosQuestionSize     = 38
	netbiosMinResponseSize  = 57 // Header + question + minimum answer header
	netbiosNameEntrySize    = 18
	netbiosNameFieldSize    = 15
	netbiosAnswerHeaderSize = 10
)

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
