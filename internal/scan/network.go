package scan

import (
	"fmt"
	"net"
)

func resolveTargets(subnet string) ([]string, error) {
	if ip := net.ParseIP(subnet); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("only IPv4 addresses are supported: %s", subnet)
		}
		return []string{ipv4.String()}, nil
	}

	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR ranges are supported: %s", subnet)
	}

	var targets []string
	for current := ipv4.Mask(ipNet.Mask); ipNet.Contains(current); incrementIP(current) {
		copyIP := make(net.IP, len(current))
		copy(copyIP, current)
		targets = append(targets, copyIP.String())
	}
	return targets, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
