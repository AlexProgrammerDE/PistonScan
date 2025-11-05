package scan

import (
	"sort"
	"strings"
)

// enrichInsightMetadata calculates the discovery sources involved in a result and derives an
// approximate insight score that the UI can use for filtering and prioritisation.
func enrichInsightMetadata(result *Result) {
	if result == nil {
		return
	}

	score := 0
	sources := make(map[string]struct{})

	addSource := func(name string) {
		if name == "" {
			return
		}
		sources[name] = struct{}{}
	}

	if result.Reachable {
		score += 2
		if len(result.LatencySamples) > 0 {
			score++
		}
		if result.TTL > 0 {
			score++
		}
		addSource("icmp")
	}

	if len(result.Hostnames) > 0 {
		score += len(result.Hostnames)
		addSource("dns")
	}

	if len(result.MDNSNames) > 0 {
		score += len(result.MDNSNames) * 2
		addSource("mdns")
	}

	if len(result.NetBIOSNames) > 0 {
		score += len(result.NetBIOSNames)
		addSource("netbios")
	}

	if len(result.LLMNRNames) > 0 {
		score += len(result.LLMNRNames)
		addSource("llmnr")
	}

	if result.SMBInfo != nil {
		if result.SMBInfo.ComputerName != "" {
			score += 2
		}
		if result.SMBInfo.Domain != "" {
			score++
		}
		addSource("smb")
	}

	if result.DeviceName != "" {
		score++
	}

	if result.MacAddress != "" {
		score += 2
		addSource("arp")
	}

	if result.Manufacturer != "" && !strings.EqualFold(result.Manufacturer, "unknown") {
		score++
		addSource("oui")
	}

	if result.OSGuess != "" && !strings.EqualFold(result.OSGuess, "unknown") {
		score++
		addSource("fingerprint")
	}

	if len(result.Services) > 0 {
		score += len(result.Services) * 2
		for _, svc := range result.Services {
			protocol := strings.ToLower(strings.TrimSpace(svc.Protocol))
			if protocol == "" {
				protocol = "tcp"
			}
			addSource(protocol)
			if svc.TLSCertInfo != "" {
				addSource("tls")
				score++
			}
		}
	}

	if result.AirPlay != nil && len(result.AirPlay.Fields) > 0 {
		score += 2
		addSource("airplay")
	}

	result.InsightScore = score

	if len(sources) == 0 {
		result.DiscoverySources = nil
		return
	}

	ordered := make([]string, 0, len(sources))
	for key := range sources {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	result.DiscoverySources = ordered
}
