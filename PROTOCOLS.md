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
  "hostnames": ["device.local"],      // DNS
  "mdnsNames": ["MyDevice"],          // mDNS/Bonjour
  "netbiosNames": ["MYDEVICE"],       // NetBIOS
  "llmnrNames": ["MyDevice"],         // LLMNR
  "deviceName": "MyDevice",           // Selected from priority order
  "services": [...]                   // DNS-SD discovered services
}
```

## Protocol Comparison Matrix

| Protocol | Port | Type | Scope | OS Support | Security |
|----------|------|------|-------|------------|----------|
| **DNS** | 53 | Unicast | Internet | All | ✅ Secure (with DNSSEC) |
| **mDNS** | 5353 | Multicast | Link-local | All modern OS | ⚠️ No auth |
| **DNS-SD** | Varies | Multicast/Unicast | Link-local/Internet | All modern OS | ⚠️ No auth |
| **NetBIOS** | 137 | Unicast/Broadcast | Subnet/WINS | Windows, Linux | ❌ Legacy, insecure |
| **LLMNR** | 5355 | Multicast | Link-local | Windows, some Linux | ⚠️ Often disabled |

## Security Considerations

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

## Performance Notes

- **DNS**: Fast (depends on DNS server response time)
- **mDNS**: Moderate (2-second timeout, multiple service queries)
- **DNS-SD**: Moderate (integrated with mDNS)
- **NetBIOS**: Fast (1-2 second timeout)
- **LLMNR**: Fast (1-second timeout)

All protocols are queried concurrently within a 4-second window to minimize total scan time per host.

## Troubleshooting

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
