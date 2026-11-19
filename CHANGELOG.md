# PistonScan 1.0.1

This release fixes two bugs in how PistonScan reads AirPlay device information. A device on the scanned network could use either bug to stop a scan.

## Fixes

- PistonScan no longer crashes when a device sends deeply nested AirPlay information. PistonScan ignores replies nested more than 16 levels deep.
- A small AirPlay reply can no longer expand into a very large amount of data and make a scan run until memory runs out. PistonScan stops reading a reply when it passes 1 MiB.

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
