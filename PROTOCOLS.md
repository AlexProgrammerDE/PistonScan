# Network Discovery Protocols

PistonScan now supports multiple network discovery protocols for comprehensive hostname resolution across different platforms and network configurations.

## Supported Protocols

### 1. DNS (Domain Name System)
**Status**: ✅ Implemented  
**Port**: UDP/TCP 53  
**Compatibility**: All platforms

DNS is the standard internet naming protocol. PistonScan uses standard DNS reverse lookups (PTR records) to resolve hostnames from IP addresses.

**How it works:**
- Uses the system's DNS resolver via Go's `net.Resolver`
- Reads `/etc/hosts` and system DNS configuration
- Performs reverse DNS lookups (PTR queries)
- Best with DHCP dynamic DNS updates

**Platform Support:**
- ✅ macOS
- ✅ iOS  
- ✅ Android
- ✅ Windows 10/11
- ✅ Linux

---

### 2. mDNS / Bonjour (Multicast DNS)
**Status**: ✅ Implemented  
**Port**: UDP 5353  
**Compatibility**: Cross-platform

mDNS is a zero-configuration service that allows name resolution without a traditional DNS server. It's the foundation of Apple's Bonjour technology.

**How it works:**
- Queries multicast address 224.0.0.251 (IPv4) or FF02::FB (IPv6)
- Devices respond with their .local hostnames
- No centralized server required
- Link-local, same subnet only

**Platform Support:**
- ✅ macOS (native Bonjour)
- ✅ iOS (native Bonjour)
- ✅ Android (with mDNS support)
- ✅ Windows 10/11 (built-in since Windows 10)
- ✅ Linux (via Avahi daemon)

---

### 3. DNS-SD (DNS Service Discovery)
**Status**: ✅ Enhanced Implementation  
**Compatibility**: Cross-platform

DNS-SD works over both mDNS and unicast DNS to discover network services and devices.

**How it works:**
- Browses for advertised services using DNS SRV and TXT records
- Can run over mDNS (.local domain) or regular DNS
- Discovers services like printers, file shares, streaming devices, etc.

**Supported Service Types (30+):**
- `_http._tcp`, `_https._tcp` - Web servers
- `_ssh._tcp` - SSH servers
- `_smb._tcp` - Windows/Samba file sharing
- `_afpovertcp._tcp` - Apple Filing Protocol
- `_airplay._tcp`, `_raop._tcp` - AirPlay devices
- `_homekit._tcp`, `_hap._tcp` - HomeKit accessories
- `_printer._tcp`, `_ipp._tcp` - Printers
- `_googlecast._tcp` - Chromecast devices
- `_spotify-connect._tcp` - Spotify Connect speakers
- `_rdp._tcp` - Remote Desktop
- And many more...

**Platform Support:**
- ✅ macOS
- ✅ iOS
- ✅ Android (limited)
- ✅ Windows 10/11
- ✅ Linux

---

### 4. NetBIOS Name Service (NBNS)
**Status**: ✅ Newly Implemented  
**Port**: UDP 137  
**Compatibility**: Windows, Linux (via Samba)

NetBIOS is a legacy Windows protocol for name resolution on local networks.

**How it works:**
- Sends NetBIOS name query packets to UDP port 137
- Uses wildcard queries to retrieve all registered names
- Filters for workstation names (types 0x00, 0x03, 0x20)
- Works on the same subnet or via WINS server
- Returns uppercase NetBIOS names (max 15 characters)

**Implementation Details:**
- Constructs raw NetBIOS query packets
- Parses NetBIOS name table responses
- Timeout: 1-2 seconds
- Filters active unique names only

**Platform Support:**
- ✅ Windows (all versions)
- ✅ Linux (via Samba)
- ⚠️ macOS (not supported)
- ⚠️ iOS (not supported)
- ⚠️ Android (not supported)

---

### 5. LLMNR (Link-Local Multicast Name Resolution)
**Status**: ✅ Newly Implemented  
**Port**: UDP 5355  
**Compatibility**: Windows, some Linux distributions

LLMNR is a Microsoft protocol designed as a fallback when DNS fails. It's commonly used in Windows networks.

**How it works:**
- Multicasts DNS-like queries to 224.0.0.252 (IPv4) or FF02::1:3 (IPv6)
- Unicast queries can also be sent directly to hosts
- Uses standard DNS packet format
- Performs reverse lookups (PTR records) to resolve IP to hostname
- Link-local, same subnet only

**Implementation Details:**
- Builds DNS-format PTR queries for reverse lookup
- Sends both multicast and unicast queries
- Parses DNS-format responses
- Timeout: 1 second
- Often disabled in enterprise networks for security reasons

**Platform Support:**
- ✅ Windows 10/11 (but often disabled)
- ✅ Windows Vista/7/8 (enabled by default)
- ⚠️ Linux (optional, systemd-resolved)
- ❌ macOS (not supported)
- ❌ iOS (not supported)
- ❌ Android (not supported)

---

### 6. UDP Port Scanning
**Status**: ✅ Newly Implemented  
**Ports**: Common UDP services (53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353, 5355)  
**Compatibility**: All platforms

UDP port scanning complements TCP scanning to detect services that only run on UDP.

**How it works:**
- Sends UDP probe packets to common service ports
- Waits for responses to detect open/listening ports
- Protocol-specific probes for DNS, SNMP, and SSDP
- Shorter timeouts due to unreliable nature of UDP

**Detected Services:**
- DNS (53) - Domain Name Service
- DHCP (67, 68) - Dynamic Host Configuration
- TFTP (69) - Trivial File Transfer
- NTP (123) - Network Time Protocol
- NetBIOS (137, 138) - Windows networking
- SNMP (161, 162) - Network management
- IPSec/IKE (500) - VPN protocols
- Syslog (514) - System logging
- RIP (520) - Routing protocol
- SSDP/UPnP (1900) - Device discovery

**Platform Support:**
- ✅ All platforms

---

### 7. SSDP/UPnP Discovery
**Status**: ✅ Newly Implemented  
**Port**: UDP 1900  
**Multicast**: 239.255.255.250:1900  
**Compatibility**: Cross-platform

SSDP (Simple Service Discovery Protocol) is used by UPnP devices to announce their presence on the network.

**How it works:**
- Sends M-SEARCH multicast discovery requests
- Devices respond with HTTP-like messages containing device info
- Extracts SERVER and LOCATION headers from responses
- Identifies routers, printers, media servers, IoT devices

**Detected Devices:**
- Home routers and gateways
- Network printers
- Media servers (DLNA/UPnP AV)
- Smart TVs and streaming devices
- IoT and smart home devices
- NAS devices

**Platform Support:**
- ✅ All platforms

---

### 8. SNMP v1/v2c Queries
**Status**: ✅ Newly Implemented  
**Port**: UDP 161  
**Compatibility**: All platforms

SNMP (Simple Network Management Protocol) provides device information when community strings are known.

**How it works:**
- Sends SNMP GET requests for sysDescr (1.3.6.1.2.1.1.1.0)
- Tries common community strings: "public", "private"
- Parses responses to identify SNMP-enabled devices
- Network devices, servers, printers commonly support SNMP

**Limitations:**
- Only queries with default community strings
- Does not attempt SNMP v3 (requires authentication)
- Brief timeout to avoid delays
- Many organizations disable SNMP or change community strings

**Detected Devices:**
- Network switches and routers
- Managed network equipment
- Printers with network management
- Servers with SNMP agents
- Network-attached storage

**Platform Support:**
- ✅ All platforms

**Security Note:**
⚠️ SNMP v1/v2c sends community strings in cleartext. SNMP v3 is more secure but requires credentials.

---

### 9. TLS Certificate Inspection
**Status**: ✅ Newly Implemented  
**Ports**: 443, 8443 (HTTPS)  
**Compatibility**: All platforms

Extracts TLS certificate information from HTTPS services to identify servers and validate security.

**How it works:**
- Establishes TLS connection to HTTPS ports
- Retrieves server certificate chain
- Extracts certificate details:
  - Common Name (CN)
  - Subject Alternative Names (SANs)
  - Expiration date
  - Issuer information

**Information Gathered:**
- Server identity (domain names)
- Certificate validity period
- Certificate authority
- Multi-domain certificates (SANs)

**Use Cases:**
- Verify server identity
- Check certificate expiration
- Identify misconfigured certificates
- Detect self-signed certificates
- Map web services and virtual hosts

**Platform Support:**
- ✅ All platforms

---

### 10. TCP SYN/Connect Scans
**Status**: ✅ Implemented (TCP Connect)  
**Ports**: Common service ports (22, 80, 443, 445, 3389, etc.)  
**Compatibility**: All platforms

TCP port scanning fingerprints running services by connecting to common ports.

**How it works:**
- Performs TCP connect scans (full three-way handshake)
- Tests common service ports
- Reads service banners where available
- Enhanced HTTP/HTTPS detection with banner grabbing
- TLS certificate inspection on HTTPS ports

**Detected Services:**
- Web servers (HTTP/HTTPS)
- SSH servers
- File sharing (SMB, AFP, NFS)
- Remote desktop (RDP, VNC)
- Database servers
- Email servers (SMTP, IMAP, POP3)
- And many more...

**Platform Support:**
- ✅ All platforms

---

### 11. ARP Sweep
**Status**: ✅ Implemented  
**Compatibility**: All platforms

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses and identifies device manufacturers.

**How it works:**
- Reads system ARP cache (/proc/net/arp on Linux)
- Executes system ARP commands as fallback
- Resolves MAC addresses to manufacturers via OUI database
- Identifies device manufacturers (Intel, Apple, Samsung, etc.)

**Information Gathered:**
- MAC addresses
- Device manufacturer (via OUI lookup)
- Physical layer device identification

**Platform Support:**
- ✅ All platforms (via system commands)

---

### 12. ICMP Echo (Ping) and TTL
**Status**: ✅ Implemented  
**Compatibility**: All platforms

ICMP echo requests (ping) test host reachability and measure latency.

**How it works:**
- Sends ICMP echo request packets
- Measures round-trip time (RTT)
- Records Time To Live (TTL) values
- Multiple attempts for accuracy
- TTL values help guess operating system

**Information Gathered:**
- Host reachability
- Network latency (milliseconds)
- Packet loss
- TTL values (OS fingerprinting)

**OS Fingerprinting via TTL:**
- TTL 64: Linux/Unix/macOS
- TTL 128: Windows
- TTL 255: Network devices (Cisco, etc.)

**Platform Support:**
- ✅ All platforms

---

## Priority Order

When multiple protocols return names for a device, PistonScan prioritizes them in this order:

1. **mDNS** - Most user-friendly, cross-platform
2. **NetBIOS** - Common on Windows networks
3. **LLMNR** - Windows fallback protocol
4. **DNS** - Universal but may not have all devices

## JSON Output Fields

Scan results now include separate fields for each protocol:

```json
{
  "ip": "192.168.1.100",
  "reachable": true,
  "latencyMs": 1.234,
  "ttl": 64,
  "hostnames": ["device.local"],      // DNS
  "mdnsNames": ["MyDevice"],          // mDNS/Bonjour
  "netbiosNames": ["MYDEVICE"],       // NetBIOS
  "llmnrNames": ["MyDevice"],         // LLMNR
  "deviceName": "MyDevice",           // Selected from priority order
  "macAddress": "AA:BB:CC:DD:EE:FF",  // ARP
  "manufacturer": "Apple Inc.",       // OUI lookup
  "osGuess": "Linux/Unix",            // TTL-based guess
  "services": [
    {
      "port": 443,
      "protocol": "tcp",
      "service": "HTTPS",
      "banner": "Server: nginx",
      "tlsCertInfo": "CN=example.com; Expires=2025-12-31"
    },
    {
      "port": 161,
      "protocol": "udp",
      "service": "SNMP",
      "banner": "SNMP (community=public)"
    },
    {
      "port": 1900,
      "protocol": "udp",
      "service": "SSDP/UPnP",
      "banner": "UPnP Device"
    }
  ]
}
```

## Protocol Comparison Matrix

| Protocol | Port | Type | Scope | OS Support | Security |
|----------|------|------|-------|------------|----------|
| **ICMP** | - | Unicast | Internet | All | ✅ Standard |
| **ARP** | - | Broadcast | Link-local | All | ⚠️ No auth |
| **TCP Scan** | Various | Unicast | Internet | All | ✅ Connection-based |
| **UDP Scan** | Various | Unicast | Internet | All | ⚠️ Unreliable |
| **DNS** | 53 | Unicast | Internet | All | ✅ Secure (with DNSSEC) |
| **mDNS** | 5353 | Multicast | Link-local | All modern OS | ⚠️ No auth |
| **DNS-SD** | Varies | Multicast/Unicast | Link-local/Internet | All modern OS | ⚠️ No auth |
| **NetBIOS** | 137 | Unicast/Broadcast | Subnet/WINS | Windows, Linux | ❌ Legacy, insecure |
| **LLMNR** | 5355 | Multicast | Link-local | Windows, some Linux | ⚠️ Often disabled |
| **SSDP/UPnP** | 1900 | Multicast | Link-local | All | ⚠️ No auth |
| **SNMP** | 161 | Unicast | Internet | Network devices | ⚠️ v1/v2c cleartext |
| **TLS Certs** | 443 | Unicast | Internet | All | ✅ Encrypted |

## Security Considerations

### ICMP/Ping
- ✅ Standard protocol, widely accepted
- ⚠️ Some networks block ICMP for security
- ℹ️ PistonScan only sends echo requests, no security risk

### ARP
- ⚠️ No authentication, vulnerable to spoofing
- ⚠️ Link-local only (reduced risk)
- ℹ️ PistonScan only reads ARP cache, doesn't send ARP requests

### TCP/UDP Port Scanning
- ✅ Standard connection-based detection
- ⚠️ May trigger IDS/IPS alerts in monitored networks
- ℹ️ PistonScan performs standard connects, not stealthy scans
- ⚠️ Some organizations prohibit port scanning

### SNMP v1/v2c
- ⚠️ Community strings sent in cleartext
- ⚠️ "public" and "private" are well-known defaults
- ⚠️ Should use SNMP v3 for production (not implemented)
- ℹ️ PistonScan only reads, doesn't modify SNMP values

### SSDP/UPnP
- ⚠️ No authentication mechanism
- ⚠️ Can expose internal network structure
- ⚠️ UPnP has history of vulnerabilities
- ℹ️ PistonScan only discovers, doesn't interact with devices

### TLS Certificate Inspection
- ✅ Secure encrypted connection
- ✅ Only reads public certificate information
- ℹ️ Uses InsecureSkipVerify to accept self-signed certs
- ℹ️ Does not validate certificate chains

### NetBIOS (NBNS)
- ⚠️ Legacy protocol with no authentication
- ⚠️ Vulnerable to spoofing attacks
- ⚠️ Should be disabled in secure environments
- ℹ️ PistonScan only queries, doesn't respond

### LLMNR
- ⚠️ Often disabled in enterprise networks due to security concerns
- ⚠️ Can be used in credential theft attacks (not applicable to PistonScan's read-only queries)
- ⚠️ Microsoft recommends disabling in favor of DNS
- ℹ️ PistonScan only queries, doesn't respond

### mDNS/Bonjour
- ⚠️ No authentication mechanism
- ⚠️ Link-local only (reduced attack surface)
- ✅ Widely deployed and generally safe for local network discovery

### DNS
- ✅ Most secure when using DNSSEC
- ✅ Centralized management
- ⚠️ Relies on proper DNS server configuration

### General Security Notes
- ✅ **All protocols are read-only** - PistonScan only queries, never responds
- ✅ **No credential handling** - No passwords or keys transmitted
- ✅ **No system modifications** - Only observes network state
- ⚠️ **Network policies** - Ensure port scanning is permitted in your environment
- ⚠️ **Privacy** - Scan results may contain sensitive network information

## Performance Notes

- **ICMP/Ping**: Very fast (< 100ms typical)
- **ARP**: Instant (reads system cache)
- **TCP Scans**: Fast (400ms timeout per port)
- **UDP Scans**: Moderate (300ms timeout per port, less reliable)
- **DNS**: Fast (depends on DNS server response time)
- **mDNS**: Moderate (2-second timeout, multiple service queries)
- **DNS-SD**: Moderate (integrated with mDNS)
- **NetBIOS**: Fast (1-2 second timeout)
- **LLMNR**: Fast (1-second timeout)
- **SNMP**: Moderate (1-second timeout)
- **SSDP/UPnP**: Moderate (1-second timeout)
- **TLS Certs**: Fast (500ms timeout)

All protocols are queried concurrently within a 4-second window to minimize total scan time per host.

## Troubleshooting

### No UDP services detected
- UDP is unreliable; responses may be lost
- Firewalls often block UDP traffic
- Many UDP services don't respond to generic probes
- Target may not be running UDP services

### No SNMP responses
- Default community strings may be changed
- SNMP may be disabled on target device
- Firewall blocking UDP port 161
- Target may use SNMP v3 (not supported)

### No SSDP/UPnP devices found
- UPnP may be disabled on devices
- Firewall blocking UDP port 1900
- Some devices only respond to multicast (not unicast)
- Target may not be a UPnP device

### No TLS certificate info
- Port 443 may not be HTTPS (some apps use raw TLS)
- Connection timeout or network issue
- Self-signed certificate with strict validation (shouldn't happen)
- Target not running HTTPS service

### No NetBIOS names discovered
- Target device may not be running Windows or Samba
- NetBIOS may be disabled on target
- Firewall blocking UDP port 137

### No LLMNR names discovered
- LLMNR often disabled on Windows 10/11 for security
- Not supported on macOS, iOS, or Android
- Firewall blocking UDP port 5355

### No mDNS names discovered
- Avahi daemon not running on Linux
- mDNS responder disabled
- Firewall blocking UDP port 5353

### No DNS names discovered
- No PTR records configured in DNS
- DNS server not responding
- Device not registered in DNS

## Implementation Details

### Code Structure
- **Main scan logic**: `internal/scan/manager.go`
- **Protocol implementations**:
  - `lookupHostnames()` - DNS
  - `lookupMDNS()` - mDNS/DNS-SD
  - `lookupNetBIOS()` - NetBIOS
  - `lookupLLMNR()` - LLMNR
- **Device name selection**: `selectDeviceName()`
- **Tests**: `internal/scan/manager_test.go`

### Dependencies
- `net` - Standard Go networking (DNS)
- `github.com/grandcat/zeroconf` - mDNS/DNS-SD
- Custom implementations for NetBIOS and LLMNR

## References

- [RFC 1001/1002](https://tools.ietf.org/html/rfc1001) - NetBIOS over TCP/IP
- [RFC 4795](https://tools.ietf.org/html/rfc4795) - LLMNR
- [RFC 6762](https://tools.ietf.org/html/rfc6762) - mDNS
- [RFC 6763](https://tools.ietf.org/html/rfc6763) - DNS-SD
