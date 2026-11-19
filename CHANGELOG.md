# PistonScan 1.0.0

PistonScan is now a native desktop app built with Rust and GPUI. It replaces the Go, Wails, and React app.

## What's new

- The redesigned interface follows the system light or dark theme.
- PistonScan detects your local IPv4 subnet and shows devices as scan results arrive.
- Select a device to view its addresses and services in the inspector.
- Use plain-language filters and keyboard shortcuts to find devices and work with scans.
- Use scan settings to adjust the number of concurrent checks, the delay, and the checks to run.
- Import or export scan snapshots as JSON. You can still open snapshots from earlier PistonScan releases.

## Breaking changes

- macOS requires 10.15.7 or later on Intel and 11 or later on Apple silicon.
- The Go and Wails app has been removed.
- PistonScan uses the system `ping` command for ICMP echo checks.
- PistonScan no longer probes SNMP with the `private` community string.
- Confirm scans of more than 1,024 addresses. A single scan can include up to 65,536 addresses.

## Install

### Linux x64

Extract the archive and run `./pistonscan` from the extracted directory. Use an X11 or Wayland session with a working Vulkan driver.

On Ubuntu 24.04, install the runtime libraries and network utilities.

```sh
sudo apt install libasound2t64 libfontconfig1 libfreetype6 libx11-6 libxcb1 \
  libxkbcommon0 libxkbcommon-x11-0 libwayland-client0 libvulkan1 libssl3t64 \
  iputils-ping net-tools
```

### Windows x64

Extract the ZIP and run `pistonscan.exe`. The executable is unsigned, so Windows SmartScreen can show a prompt.

### macOS

Extract the ZIP and move `PistonScan.app` to Applications. The app has an ad hoc signature and no Apple notarization. Gatekeeper will warn on first launch.

Right-click the app and choose Open. If macOS does not offer Open, use **Privacy & Security** in System Settings or run the following command from the folder that contains the app.

```sh
xattr -dr com.apple.quarantine PistonScan.app
```
