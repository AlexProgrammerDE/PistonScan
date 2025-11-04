package scan

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

func lookupHostnames(ctx context.Context, host string) []string {
	// Use a resolver that prefers the cgo resolver, which reads /etc/hosts
	// and uses the system's DNS configuration
	resolver := &net.Resolver{
		PreferGo: false,
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, host)
	if err != nil {
		// Don't log error, just return nil - DNS reverse lookups often fail
		// in home/small office networks without proper PTR records
		return nil
	}
	return uniqueStrings(names)
}

func lookupMDNS(ctx context.Context, host string) []string {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil
	}

	// Create a channel for internal use that won't be closed manually
	internalEntries := make(chan *zeroconf.ServiceEntry, 10)

	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resultsMu := sync.Mutex{}
	results := make(map[string]struct{})

	// Helper to add hostname results
	addHostnameResults := func(entry *zeroconf.ServiceEntry) {
		resultsMu.Lock()
		defer resultsMu.Unlock()
		if entry.Instance != "" {
			results[entry.Instance] = struct{}{}
		}
		if entry.Service != "" {
			service := strings.TrimSuffix(entry.Service, ".")
			if service != "" {
				results[service] = struct{}{}
			}
		}
		if entry.HostName != "" {
			// Clean up hostname (remove trailing dot)
			hostname := strings.TrimSuffix(entry.HostName, ".")
			if hostname != "" {
				results[hostname] = struct{}{}
			}
		}
		for _, txt := range entry.Text {
			if txt == "" {
				continue
			}
			if strings.Contains(txt, "=") {
				parts := strings.SplitN(txt, "=", 2)
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				value := strings.TrimSpace(parts[1])
				if value == "" {
					continue
				}
				switch key {
				case "fn", "id", "model", "name", "md":
					results[value] = struct{}{}
				}
			} else {
				results[txt] = struct{}{}
			}
		}
	}

	// Collect results in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range internalEntries {
			// Check all IPv4 addresses for a match
			for _, ipv4 := range entry.AddrIPv4 {
				if ipv4.String() == host {
					addHostnameResults(entry)
					break
				}
			}
			// Also check IPv6 addresses
			for _, ipv6 := range entry.AddrIPv6 {
				if ipv6.String() == host {
					addHostnameResults(entry)
					break
				}
			}
		}
	}()

	// Browse for all service types to find devices
	// This is a broader search that will find more devices
	// Enhanced list of service types for better device discovery
	serviceTypes := []string{
		"_services._dns-sd._udp", // Service discovery
		"_workstation._tcp",      // Workstations
		"_device-info._tcp",      // Device info
		"_http._tcp",             // HTTP servers
		"_https._tcp",            // HTTPS servers
		"_ssh._tcp",              // SSH servers
		"_smb._tcp",              // SMB/Samba file sharing
		"_afpovertcp._tcp",       // Apple Filing Protocol
		"_ftp._tcp",              // FTP servers
		"_printer._tcp",          // Printers
		"_ipp._tcp",              // Internet Printing Protocol
		"_pdl-datastream._tcp",   // Printer PDL data stream
		"_airplay._tcp",          // AirPlay
		"_raop._tcp",             // Remote Audio Output Protocol (AirPlay audio)
		"_homekit._tcp",          // HomeKit devices
		"_hap._tcp",              // HomeKit Accessory Protocol
		"_companion-link._tcp",   // Apple devices
		"_sleep-proxy._udp",      // Bonjour sleep proxy
		"_rdp._tcp",              // Remote Desktop Protocol
		"_rfb._tcp",              // VNC (Remote Frame Buffer)
		"_telnet._tcp",           // Telnet
		"_nfs._tcp",              // NFS file sharing
		"_webdav._tcp",           // WebDAV
		"_daap._tcp",             // Digital Audio Access Protocol (iTunes)
		"_dpap._tcp",             // Digital Photo Access Protocol
		"_dacp._tcp",             // Digital Audio Control Protocol
		"_googlecast._tcp",       // Google Cast/Chromecast
		"_spotify-connect._tcp",  // Spotify Connect
		"_sonos._tcp",            // Sonos speakers
	}

	// Use a WaitGroup to track active Browse operations
	var browseWg sync.WaitGroup
	var forwardWg sync.WaitGroup

	// Create a wrapper channel for each Browse call to avoid the race condition
	// where multiple Browse goroutines try to close the same channel
	for _, serviceType := range serviceTypes {
		select {
		case <-queryCtx.Done():
			break
		default:
			browseWg.Add(1)
			entries := make(chan *zeroconf.ServiceEntry, 10)

			go func(service string, ch chan *zeroconf.ServiceEntry) {
				defer browseWg.Done()
				_ = resolver.Browse(queryCtx, service, "local.", ch)
			}(serviceType, entries)

			forwardWg.Add(1)
			go func(ch chan *zeroconf.ServiceEntry) {
				defer forwardWg.Done()
				for entry := range ch {
					internalEntries <- entry
				}
			}(entries)
		}
	}

	go func() {
		browseWg.Wait()
		forwardWg.Wait()
		close(internalEntries)
	}()

	<-queryCtx.Done()

	// Wait for the result collector to finish
	<-done

	resultsMu.Lock()
	defer resultsMu.Unlock()
	if len(results) == 0 {
		return nil
	}
	out := make([]string, 0, len(results))
	for key := range results {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
