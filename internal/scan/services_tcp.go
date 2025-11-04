package scan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	defaultServicePorts = []int{80, 443, 8080, 8443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 3000, 4200, 5000, 7000, 22, 445, 3389, 5353, 1900, 21, 23, 25, 110, 143, 139, 135, 548, 631, 554, 5357, 8765, 8888, 53}
	knownServiceNames   = map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		67:   "DHCP Server",
		68:   "DHCP Client",
		69:   "TFTP",
		80:   "HTTP",
		110:  "POP3",
		123:  "NTP",
		135:  "MS RPC",
		137:  "NetBIOS Name",
		138:  "NetBIOS Datagram",
		139:  "NetBIOS Session",
		143:  "IMAP",
		161:  "SNMP",
		162:  "SNMP Trap",
		443:  "HTTPS",
		445:  "SMB",
		500:  "IKE/IPSec",
		514:  "Syslog",
		520:  "RIP",
		548:  "AFP",
		554:  "RTSP",
		631:  "IPP",
		700:  "EPP",
		1900: "SSDP/UPnP",
		3389: "RDP",
		4200: "Angular Dev",
		5000: "UPnP/WS",
		5353: "mDNS",
		5355: "LLMNR",
		5357: "Web Services",
		7000: "AirPlay",
		8000: "HTTP Dev",
		8888: "HTTP Alt",
	}
)

func scanServices(ctx context.Context, host string, ports []int) []ServiceInfo {
	if len(ports) == 0 {
		return nil
	}

	dialer := &net.Dialer{Timeout: 400 * time.Millisecond}
	concurrency := min(len(ports), 32)
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

			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			defer conn.Close()

			_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
			banner := readServiceBanner(conn, host, port)

			// Check for TLS certificate on HTTPS ports
			var tlsInfo string
			if port == 443 || port == 8443 {
				tlsInfo = getTLSCertInfo(ctx, host, port)
			}

			name := knownServiceNames[port]
			if name == "" {
				name = fmt.Sprintf("TCP %d", port)
			}

			service := ServiceInfo{
				Port:        port,
				Protocol:    "tcp",
				Service:     name,
				Banner:      banner,
				TLSCertInfo: tlsInfo,
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

func readServiceBanner(conn net.Conn, host string, port int) string {
	if isHTTPPort(port) {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
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
