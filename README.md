# PistonScan

## About

PistonScan is a cross-platform network scanner built with Wails (Go + React). It provides comprehensive network discovery using multiple protocols for device detection, service fingerprinting, and security assessment.

### Core Network Probes

- **ICMP Echo (Ping)** - Host reachability and latency measurement with TTL-based OS fingerprinting
- **ARP Sweep** - MAC address resolution and manufacturer identification via OUI lookup
- **TCP Connect Scans** - Service detection on common ports with banner grabbing
- **UDP Port Probes** - UDP service detection (DNS, DHCP, SNMP, SSDP, etc.)

### Service Discovery Protocols

PistonScan supports multiple discovery protocols for maximum compatibility across different platforms:

- **DNS** - Standard DNS reverse lookups (all platforms)
- **mDNS/Bonjour** - Zero-configuration networking (macOS, iOS, Android, Windows 10+, Linux)
- **DNS-SD** - Service discovery with 30+ service types (cross-platform)
- **NetBIOS (NBNS)** - Windows name resolution, also via Samba on Linux
- **LLMNR** - Link-Local Multicast Name Resolution (Windows, some Linux)
- **SSDP/UPnP** - Universal Plug and Play device discovery (routers, printers, IoT devices)
- **SNMP v1/v2c** - Network device management protocol queries with common community strings
- **TLS Certificate Inspection** - Extract certificate details from HTTPS services

For detailed information about each protocol, see [PROTOCOLS.md](PROTOCOLS.md).

This is based on the official Wails React-TS template.

You can configure the project by editing `wails.json`. More information about the project settings can be found
here: https://wails.io/docs/reference/project-config

## Live Development

To run in live development mode, run `wails dev` in the project directory. This will run a Vite development
server that will provide very fast hot reload of your frontend changes. If you want to develop in a browser
and have access to your Go methods, there is also a dev server that runs on http://localhost:34115. Connect
to this in your browser, and you can call your Go code from devtools.

## Building

To build a redistributable, production mode package, use `wails build`.
