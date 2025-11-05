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
	defaultServicePorts = []int{
		21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 389, 443, 445, 465, 502, 515, 587, 631, 636, 700, 993, 995,
		1433, 1521, 1723, 1883, 2049, 27017, 3000, 3128, 3268, 3306, 3389, 4200, 5000, 5432, 5601, 5671, 5672, 5900,
		5984, 5985, 5986, 6379, 7000, 7547, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8080,
		8081, 8082, 8083, 8086, 8088, 8291, 8443, 8530, 8728, 8729, 8888, 9000, 9042, 9100, 9200, 9443, 11211,
	}
	knownServiceNames = map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP Server",
		68:    "DHCP Client",
		69:    "TFTP",
		80:    "HTTP",
		81:    "HTTP Alt",
		110:   "POP3",
		123:   "NTP",
		135:   "MS RPC",
		137:   "NetBIOS Name",
		138:   "NetBIOS Datagram",
		139:   "NetBIOS Session",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP Trap",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		500:   "IKE/IPSec",
		502:   "Modbus/TCP",
		514:   "Syslog",
		515:   "LPD",
		520:   "RIP",
		548:   "AFP",
		554:   "RTSP",
		587:   "SMTP Submission",
		631:   "IPP",
		636:   "LDAPS",
		700:   "EPP",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle DB",
		1723:  "PPTP",
		1883:  "MQTT",
		1900:  "SSDP/UPnP",
		2049:  "NFS",
		27017: "MongoDB",
		3000:  "HTTP Dev",
		3128:  "Squid Proxy",
		3268:  "AD Global Catalog",
		3306:  "MySQL",
		3389:  "RDP",
		4200:  "Angular Dev",
		5000:  "UPnP/WS",
		5353:  "mDNS",
		5355:  "LLMNR",
		5357:  "Web Services",
		5432:  "PostgreSQL",
		5601:  "Kibana",
		5671:  "AMQP TLS",
		5672:  "AMQP",
		5900:  "VNC",
		5984:  "CouchDB",
		5985:  "WinRM HTTP",
		5986:  "WinRM HTTPS",
		6379:  "Redis",
		7000:  "AirPlay",
		7547:  "TR-069",
		8000:  "HTTP Dev",
		8001:  "HTTP Dev",
		8002:  "HTTP Dev",
		8003:  "HTTP Dev",
		8004:  "HTTP Dev",
		8005:  "HTTP Dev",
		8006:  "HTTP Dev",
		8007:  "HTTP Dev",
		8008:  "HTTP Dev",
		8009:  "HTTP Dev",
		8010:  "HTTP Dev",
		8080:  "HTTP Alt",
		8081:  "HTTP Alt",
		8082:  "HTTP Alt",
		8083:  "HTTP Alt",
		8086:  "InfluxDB",
		8088:  "HTTP Alt",
		8291:  "MikroTik WinBox",
		8443:  "HTTPS Alt",
		8530:  "WSUS",
		8728:  "MikroTik API",
		8729:  "MikroTik API TLS",
		8888:  "HTTP Alt",
		9000:  "HTTP Alt",
		9042:  "Cassandra",
		9100:  "JetDirect",
		9200:  "Elasticsearch",
		9443:  "HTTPS Alt",
		11211: "Memcached",
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
			switch port {
			case 443, 5986, 8443, 8729, 9443:
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
	reader := bufio.NewReader(conn)
	if isHTTPPort(port) {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		var (
			statusLine string
			serverLine string
			authLine   string
		)
		for i := 0; i < 12; i++ {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				break
			}
			lower := strings.ToLower(trimmed)
			if i == 0 {
				statusLine = trimmed
			}
			if serverLine == "" && strings.HasPrefix(lower, "server:") {
				serverLine = strings.TrimSpace(trimmed[len("server:"):])
			}
			if authLine == "" && strings.HasPrefix(lower, "www-authenticate:") {
				authLine = trimmed
			}
		}
		switch {
		case serverLine != "":
			return serverLine
		case authLine != "":
			return authLine
		case statusLine != "":
			return statusLine
		default:
			return ""
		}
	}
	// VNC servers send RFB protocol version immediately upon connection
	// Example: "RFB 003.008\n"
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 81, 3000, 3128, 4200, 5000, 5601, 5984, 5985, 7000, 7547, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8086, 8088, 8530, 8888, 9000, 9200:
		return true
	default:
		return false
	}
}
