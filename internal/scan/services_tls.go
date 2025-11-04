package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// getTLSCertInfo extracts TLS certificate information from HTTPS endpoints
func getTLSCertInfo(ctx context.Context, host string, port int) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}

	cert := state.PeerCertificates[0]
	var info bytes.Buffer

	// Extract key certificate details
	if cert.Subject.CommonName != "" {
		fmt.Fprintf(&info, "CN=%s", cert.Subject.CommonName)
	}

	if len(cert.DNSNames) > 0 {
		if info.Len() > 0 {
			info.WriteString("; ")
		}
		fmt.Fprintf(&info, "SANs=%s", strings.Join(cert.DNSNames[:min(3, len(cert.DNSNames))], ","))
	}

	if !cert.NotAfter.IsZero() {
		if info.Len() > 0 {
			info.WriteString("; ")
		}
		fmt.Fprintf(&info, "Expires=%s", cert.NotAfter.Format("2006-01-02"))
	}

	if cert.Issuer.CommonName != "" && cert.Issuer.CommonName != cert.Subject.CommonName {
		if info.Len() > 0 {
			info.WriteString("; ")
		}
		fmt.Fprintf(&info, "Issuer=%s", cert.Issuer.CommonName)
	}

	return info.String()
}
