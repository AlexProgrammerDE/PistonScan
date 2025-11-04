package scan

func selectDeviceName(mdns, netbios, llmnr, hostnames []string) string {
	// Prioritize mDNS names as they are most reliable and user-friendly
	if len(mdns) > 0 {
		return mdns[0]
	}
	// NetBIOS names are common on Windows networks
	if len(netbios) > 0 {
		return netbios[0]
	}
	// LLMNR is also common on Windows
	if len(llmnr) > 0 {
		return llmnr[0]
	}
	// Fall back to DNS hostnames
	if len(hostnames) > 0 {
		return hostnames[0]
	}
	return ""
}

func guessOS(ttl int, services []ServiceInfo) string {
	if ttl == 0 {
		ttl = 64
	}
	switch {
	case ttl <= 64:
		if hasService(services, 548) || hasService(services, 7000) {
			return "Apple / macOS"
		}
		return "Linux / Unix"
	case ttl <= 128:
		if hasService(services, 445) || hasService(services, 3389) {
			return "Windows"
		}
		return "Windows (likely)"
	case ttl >= 200:
		return "Network Appliance"
	default:
		return "Unknown"
	}
}

func hasService(services []ServiceInfo, port int) bool {
	for _, svc := range services {
		if svc.Port == port {
			return true
		}
	}
	return false
}
