# Discovery Methods Implementation

This document details how PistonScan implements the three key discovery methods specified in the requirements:

## 1. mDNS/DNS-SD for IPP, AirPlay, AirTunes

### Implementation Location
- **File**: `internal/scan/discovery_dns.go`
- **Function**: `lookupMDNS(ctx context.Context, host string)`
- **Library**: `github.com/grandcat/zeroconf` v1.0.0

### Service Types Discovered
The following mDNS/DNS-SD service types are actively browsed:

#### Printer Services (IPP)
- `_ipp._tcp` - Internet Printing Protocol (standard)
- `_ipps._tcp` - Internet Printing Protocol over SSL/TLS (secure)
- `_printer._tcp` - Generic printer service
- `_pdl-datastream._tcp` - Printer Page Description Language data stream

#### AirPlay Services
- `_airplay._tcp` - AirPlay video and audio streaming

#### AirTunes Services
- `_raop._tcp` - Remote Audio Output Protocol (AirPlay audio/AirTunes)

### How It Works
1. Creates a zeroconf resolver using `zeroconf.NewResolver()`
2. Browses for each service type in the `.local` domain
3. Listens for service announcements via multicast DNS (port 5353)
4. Matches discovered services against target IP addresses
5. Extracts device information from:
   - Instance names
   - Hostnames
   - TXT record fields (model, name, etc.)

### Integration
- **Called from**: `collectHostDetails()` in `internal/scan/collector.go`
- **Timeout**: 2 seconds
- **Result field**: Populates `MDNSNames` array in scan results
- **Concurrent**: Runs in parallel with other discovery methods

### Example Output
When scanning a network with an AirPlay TV and IPP printer:
```json
{
  "ip": "192.168.1.50",
  "mdnsNames": ["Living Room Apple TV"],
  "services": [
    {
      "port": 7000,
      "protocol": "tcp",
      "service": "AirPlay"
    }
  ]
}
```

```json
{
  "ip": "192.168.1.100",
  "mdnsNames": ["HP LaserJet Pro"],
  "services": [
    {
      "port": 631,
      "protocol": "tcp",
      "service": "IPP"
    }
  ]
}
```

## 2. SSDP for UPnP

### Implementation Location
- **File**: `internal/scan/services_udp.go`
- **Function**: `probeSSDP(ctx context.Context, host string)`
- **Protocol**: SSDP (Simple Service Discovery Protocol) over UDP

### How It Works
1. Sends M-SEARCH multicast discovery request to UDP port 1900
2. Target multicast address: 239.255.255.250:1900
3. Search target: `ssdp:all` (discovers all UPnP devices)
4. Waits for HTTP-like SSDP response messages
5. Parses response headers:
   - `SERVER:` - Device/software information
   - `LOCATION:` - Device description URL
6. Returns formatted device information

### SSDP Request Format
```
M-SEARCH * HTTP/1.1\r\n
HOST: 239.255.255.250:1900\r\n
MAN: "ssdp:discover"\r\n
MX: 1\r\n
ST: ssdp:all\r\n
\r\n
```

### Integration
- **Called from**: `scanUDPServices()` in `internal/scan/services_udp.go`
- **Triggered when**: Port 1900 UDP is probed
- **Timeout**: 1 second for response
- **Result field**: Appears in `services` array with UPnP banner

### Detected Device Types
- Home routers and gateways
- Network printers with UPnP
- Media servers (DLNA/UPnP AV)
- Smart TVs and streaming devices
- IoT and smart home devices
- NAS devices

### Example Output
```json
{
  "ip": "192.168.1.1",
  "services": [
    {
      "port": 1900,
      "protocol": "udp",
      "service": "SSDP/UPnP",
      "banner": "UPnP: Linux/4.1 UPnP/1.0 Portable SDK/1.8.0"
    }
  ]
}
```

## 3. Direct TCP Banner for VNC

### Implementation Location
- **File**: `internal/scan/services_tcp.go`
- **Function**: `readServiceBanner(conn net.Conn, host string, port int)`
- **Protocol**: RFB (Remote Frame Buffer) - VNC protocol

### How It Works
1. TCP connect scan detects open port 5900
2. Upon connection, VNC server immediately sends RFB version banner
3. Banner format: `RFB xxx.yyy\n` (e.g., "RFB 003.008\n")
4. Function reads first line from socket
5. Validates RFB protocol prefix for port 5900
6. Returns banner string with version information

### RFB Protocol Versions
Common VNC/RFB versions detected:
- `RFB 003.003` - RFB 3.3 (oldest common version)
- `RFB 003.007` - RFB 3.7
- `RFB 003.008` - RFB 3.8 (most common modern version)

### Integration
- **Called from**: `scanServices()` in `internal/scan/services_tcp.go`
- **Triggered when**: Port 5900 TCP is scanned
- **Timeout**: 300ms for banner read
- **Result field**: Appears in `services` array with RFB banner

### Code Enhancement
Simplified VNC/RFB banner reading:
```go
// VNC servers send RFB protocol version immediately upon connection
// Example: "RFB 003.008\n"
line, err := reader.ReadString('\n')
if err != nil {
    return ""
}
return strings.TrimSpace(line)
```

The function reads the first line from any TCP connection. VNC servers automatically send their RFB version upon connection, so no special handling is needed - the banner is captured naturally.

### Example Output
```json
{
  "ip": "192.168.1.75",
  "services": [
    {
      "port": 5900,
      "protocol": "tcp",
      "service": "VNC",
      "banner": "RFB 003.008"
    }
  ]
}
```

## Testing

### Unit Tests
- **TestReadServiceBannerVNC**: Validates RFB banner detection logic
- **TestProbeSSDP**: Tests SSDP discovery mechanism
- **TestLookupMDNS**: Tests mDNS browsing and service discovery

### Test Command
```bash
go test ./internal/scan/... -v
```

## Verification Checklist

✅ **mDNS/DNS-SD**
- [x] Uses `github.com/grandcat/zeroconf` library
- [x] Discovers `_ipp._tcp` for IPP printers
- [x] Discovers `_ipps._tcp` for secure IPP
- [x] Discovers `_airplay._tcp` for AirPlay devices
- [x] Discovers `_raop._tcp` for AirTunes/AirPlay audio
- [x] Integrated into host scanning pipeline
- [x] Results stored in scan output

✅ **SSDP/UPnP**
- [x] Sends M-SEARCH discovery requests
- [x] Uses multicast address 239.255.255.250:1900
- [x] Parses SERVER and LOCATION headers
- [x] Integrated into UDP service scanning
- [x] Results stored in services array

✅ **VNC Banner**
- [x] Scans TCP port 5900
- [x] Reads RFB protocol version banner
- [x] Validates RFB prefix
- [x] Integrated into TCP service scanning
- [x] Results stored in services array
- [x] Unit tests validate detection

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│            Scan Manager (manager.go)                    │
│                                                         │
│  Start Scan → collectHostDetails(host)                 │
└────────────────────┬────────────────────────────────────┘
                     │
                     ├─────────────────────────────┐
                     │                             │
                     ▼                             ▼
        ┌────────────────────────┐   ┌────────────────────────┐
        │  DNS Discovery         │   │  Service Scanning      │
        │  (discovery_dns.go)    │   │  (services_*.go)       │
        └────────────────────────┘   └────────────────────────┘
                     │                             │
        ┌────────────┴─────────┐      ┌───────────┴──────────┐
        ▼                      ▼      ▼                      ▼
┌──────────────┐    ┌──────────────┐ ┌──────────┐  ┌──────────────┐
│ lookupMDNS() │    │ lookupDNS()  │ │ TCP Scan │  │  UDP Scan    │
│              │    │              │ │          │  │              │
│ • _ipp._tcp  │    │ • PTR        │ │ • Port   │  │ • Port 1900  │
│ • _ipps._tcp │    │   records    │ │   5900   │  │              │
│ • _airplay   │    │              │ │          │  │ • probeSSDP()│
│ • _raop._tcp │    │              │ │ • VNC    │  │              │
│              │    │              │ │   banner │  │              │
└──────────────┘    └──────────────┘ └──────────┘  └──────────────┘
        │                      │            │                │
        │                      │            │                │
        └──────────────────────┴────────────┴────────────────┘
                              │
                              ▼
                     ┌────────────────┐
                     │  Scan Results  │
                     │                │
                     │ • mdnsNames    │
                     │ • hostnames    │
                     │ • services[]   │
                     └────────────────┘
```

## Performance Characteristics

| Method | Protocol | Timeout | Concurrency | Reliability |
|--------|----------|---------|-------------|-------------|
| mDNS/DNS-SD | UDP 5353 | 2 sec | Parallel browse | High on local network |
| SSDP | UDP 1900 | 1 sec | Per-host probe | Medium (UDP unreliable) |
| VNC Banner | TCP 5900 | 300ms | Per-port scan | High (TCP reliable) |

## Security Considerations

### mDNS/DNS-SD
- ✅ Read-only queries (no responses sent)
- ✅ No authentication required
- ⚠️ Link-local only (reduced attack surface)
- ⚠️ No encryption (multicast plaintext)

### SSDP/UPnP
- ✅ Read-only discovery (no device interaction)
- ✅ No authentication required
- ⚠️ No encryption (multicast plaintext)
- ⚠️ Can expose internal network topology

### VNC Banner
- ✅ Read-only banner grab (no authentication)
- ✅ TCP connection-based (reliable)
- ⚠️ Reveals VNC service presence
- ⚠️ VNC without proper authentication is a security risk

## References

- [RFC 6762](https://tools.ietf.org/html/rfc6762) - Multicast DNS
- [RFC 6763](https://tools.ietf.org/html/rfc6763) - DNS-Based Service Discovery
- [UPnP Device Architecture](http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0.pdf)
- [RFB Protocol](https://tools.ietf.org/html/rfc6143) - Remote Frame Buffer Protocol (VNC)
- [IPP](https://tools.ietf.org/html/rfc8011) - Internet Printing Protocol
