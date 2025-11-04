# PistonScan

## About

PistonScan is a cross-platform network scanner built with Wails (Go + React). It provides comprehensive network discovery using multiple protocols for hostname resolution.

### Network Discovery Protocols

PistonScan supports multiple discovery protocols for maximum compatibility across different platforms:

- **DNS** - Standard DNS reverse lookups (all platforms)
- **mDNS/Bonjour** - Zero-configuration networking (macOS, iOS, Android, Windows 10+, Linux)
- **DNS-SD** - Service discovery with 30+ service types (cross-platform)
- **NetBIOS (NBNS)** - Windows name resolution, also via Samba on Linux
- **LLMNR** - Link-Local Multicast Name Resolution (Windows, some Linux)

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
