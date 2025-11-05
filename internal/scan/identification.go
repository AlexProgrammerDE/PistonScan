package scan

import "strings"

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

func guessOS(services []ServiceInfo) string {
	if len(services) == 0 {
		return "Unknown"
	}

	var windowsScore, linuxScore, appleScore float64

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
		case 137, 138, 5355:
			windowsScore += 2
		case 5357:
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
		case 631:
			linuxScore += 2
		case 161, 162:
			linuxScore += 1
		}

		if strings.Contains(name, "smb") || strings.Contains(name, "ms rpc") || strings.Contains(name, "rdp") {
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
		if strings.Contains(banner, "openssh") || strings.Contains(banner, "linux") || strings.Contains(banner, "ubuntu") || strings.Contains(banner, "debian") || strings.Contains(banner, "centos") || strings.Contains(banner, "red hat") {
			linuxScore += 3
		}
		if strings.Contains(banner, "samba") {
			linuxScore += 1.5
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
	}

	// Find the top two candidates for confidence comparison
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
