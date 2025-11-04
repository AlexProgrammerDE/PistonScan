package scan

import (
	"context"
	"errors"
	"sync"
	"time"
)

func collectHostDetails(ctx context.Context, host string) Result {
	result := Result{IP: host}

	summary, err := pingHost(ctx, host, 3)
	result.Attempts = summary.Attempts
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return result
		}
		result.Error = err.Error()
		return result
	}

	if !summary.Reachable {
		result.Error = "no response"
		return result
	}

	result.Reachable = true
	result.LatencyMs = summary.AvgLatency.Seconds() * 1000
	result.LatencySamples = durationsToMillis(summary.Latencies)
	result.TTL = summary.TTL

	infoCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	// Run all lookup operations in parallel to ensure they all complete
	var wg sync.WaitGroup
	var hostnames, mdnsNames, netbiosNames, llmnrNames []string
	var mac string
	var services []ServiceInfo

	// Launch parallel lookup operations
	wg.Add(1)
	go func() {
		defer wg.Done()
		hostnames = lookupHostnames(infoCtx, host)
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		mdnsNames = lookupMDNS(infoCtx, host)
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		netbiosNames = lookupNetBIOS(infoCtx, host)
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		llmnrNames = lookupLLMNR(infoCtx, host)
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		mac = lookupMACAddress(infoCtx, host)
	}()
	
	// Scan TCP and UDP services separately, then merge results
	var tcpServices, udpServices []ServiceInfo
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpServices = scanServices(infoCtx, host, defaultServicePorts)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		udpServices = scanUDPServices(infoCtx, host, defaultUDPPorts)
	}()

	wg.Wait()

	// Merge TCP and UDP services
	services = append(tcpServices, udpServices...)

	manufacturer := lookupManufacturer(mac)
	deviceName := selectDeviceName(mdnsNames, netbiosNames, llmnrNames, hostnames)
	osGuess := guessOS(summary.TTL, services)

	result.Hostnames = hostnames
	result.MDNSNames = mdnsNames
	result.NetBIOSNames = netbiosNames
	result.LLMNRNames = llmnrNames
	result.MacAddress = mac
	result.Manufacturer = manufacturer
	result.Services = services
	result.DeviceName = deviceName
	result.OSGuess = osGuess

	return result
}
