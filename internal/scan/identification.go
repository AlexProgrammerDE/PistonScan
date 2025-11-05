package scan

import "strings"

func selectDeviceName(mdns, netbios, llmnr, hostnames []string, smb *SMBInfo, airplay *AirPlayInfo) string {
	// Prioritize mDNS names as they are most reliable and user-friendly
	if len(mdns) > 0 {
		return mdns[0]
	}
	// Prefer AirPlay-advertised names when available
	if airplay != nil && len(airplay.Fields) > 0 {
		if name := airplay.Fields["name"]; name != "" {
			return name
		}
		if name := airplay.Fields["deviceName"]; name != "" {
			return name
		}
		if name := airplay.Fields["pi"]; name != "" {
			return name
		}
		if name := airplay.Fields["deviceid"]; name != "" {
			return name
		}
		if name := airplay.Fields["model"]; name != "" {
			return name
		}
	}
	// Fall back to SMB workstation data before legacy name sources
	if smb != nil {
		if name := strings.TrimSpace(smb.ComputerName); name != "" {
			return name
		}
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

func guessOS(services []ServiceInfo) string {
	if len(services) == 0 {
		return "Unknown"
	}

	var windowsScore, linuxScore, appleScore float64
	var networkScore, printerScore float64

	networkVendors := []string{
		"cisco", "routeros", "mikrotik", "ubiquiti", "ubnt", "edgeos", "juniper", "aruba", "fortinet", "fortigate", "meraki",
		"tp-link", "tplink", "netgear", "d-link", "brocade", "ruckus", "palo alto", "pan-os", "sonicwall", "watchguard", "draytek",
	}
	printerVendors := []string{
		"hp", "hewlett-packard", "jetdirect", "printer", "xerox", "ricoh", "kyocera", "konica", "minolta", "sharp", "lexmark",
		"brother", "canon", "epson", "oki", "sindoh", "bizhub",
	}

	addScore := func(service ServiceInfo) {
		name := strings.ToLower(service.Service)
		banner := strings.ToLower(service.Banner)
		protocol := strings.ToLower(service.Protocol)

		switch service.Port {
		case 445, 3389:
			if protocol == "tcp" {
				windowsScore += 4
			}
		case 135, 139:
			if protocol == "tcp" {
				windowsScore += 3
			}
		case 137, 138, 3268, 5355:
			windowsScore += 2
		case 389, 5357, 5985, 5986:
			windowsScore += 1.5
		case 1433:
			windowsScore += 1.5
		case 548, 7000:
			if protocol == "tcp" {
				appleScore += 4
			}
		case 5353:
			appleScore += 1
		case 22:
			if protocol == "tcp" {
				linuxScore += 2.5
			}
		case 2049, 3306, 5432:
			linuxScore += 1.5
		case 631:
			linuxScore += 1.5
			printerScore += 3
		case 515, 9100:
			printerScore += 4
		case 161, 162:
			networkScore += 2.5
		case 1723, 502, 7547, 8291, 8728, 8729:
			networkScore += 4
		}

		if strings.Contains(name, "smb") || strings.Contains(name, "ms rpc") || strings.Contains(name, "rdp") || strings.Contains(name, "winrm") || strings.Contains(name, "ldap") {
			windowsScore += 2
		}
		if strings.Contains(banner, "microsoft") || strings.Contains(banner, "windows") {
			windowsScore += 3
		}
		if strings.Contains(name, "airplay") || strings.Contains(name, "afp") {
			appleScore += 3
		}
		if strings.Contains(banner, "apple") || strings.Contains(banner, "mac os") || strings.Contains(banner, "ios") || strings.Contains(banner, "ipad") {
			appleScore += 3
		}
		if strings.Contains(name, "ssh") {
			linuxScore += 2
		}
		if strings.Contains(name, "redis") || strings.Contains(name, "postgres") || strings.Contains(name, "mysql") || strings.Contains(name, "nfs") {
			linuxScore += 1.5
		}
		if strings.Contains(banner, "openssh") || strings.Contains(banner, "linux") || strings.Contains(banner, "ubuntu") || strings.Contains(banner, "debian") || strings.Contains(banner, "centos") || strings.Contains(banner, "red hat") || strings.Contains(banner, "synology") || strings.Contains(banner, "qnap") {
			linuxScore += 3
		}
		if strings.Contains(banner, "samba") {
			linuxScore += 1.5
		}
		for _, keyword := range networkVendors {
			if strings.Contains(name, keyword) || strings.Contains(banner, keyword) {
				networkScore += 3
				break
			}
		}
		if strings.Contains(name, "router") || strings.Contains(name, "switch") || strings.Contains(banner, "router") || strings.Contains(banner, "switch") {
			networkScore += 2.5
		}
		if strings.Contains(name, "winbox") {
			networkScore += 3
		}
		for _, keyword := range printerVendors {
			if strings.Contains(name, keyword) || strings.Contains(banner, keyword) {
				printerScore += 3
				break
			}
		}
	}

	for _, svc := range services {
		addScore(svc)
	}

	type candidate struct {
		name  string
		score float64
	}

	candidates := []candidate{
		{name: "Windows", score: windowsScore},
		{name: "Linux / Unix", score: linuxScore},
		{name: "Apple / macOS", score: appleScore},
		{name: "Network Infrastructure", score: networkScore},
		{name: "Printer / Scanner", score: printerScore},
	}

	var top candidate
	var second candidate
	for _, c := range candidates {
		if c.score > top.score {
			second = top
			top = c
		} else if c.score > second.score {
			second = c
		}
	}

	if top.score < 3 {
		return "Unknown"
	}
	if top.score-second.score < 1.5 {
		return "Unknown"
	}

	return top.name
}
