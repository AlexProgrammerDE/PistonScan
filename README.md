# PistonScan

PistonScan is a native desktop IP scanner built with Rust and GPUI. Scan one IPv4 address or a subnet and watch results arrive as each host finishes. Filter by reachability or insight score, sort by latency or IP address, and expand a row to see how PistonScan identified the device. Import and export JSON snapshots to save or revisit a scan.

PistonScan starts with ICMP echo. For hosts that respond, it checks DNS, mDNS, NetBIOS, LLMNR, SMB, the neighbor cache, and common TCP and UDP services. It can also read TLS certificates and AirPlay metadata. See [the protocol reference](PROTOCOLS.md) for details.

## Platform requirements

| Platform | Requirements |
| --- | --- |
| macOS | macOS 10.15.7 or later on Intel with Metal. macOS 11 or later on Apple silicon. Install Xcode with the Metal toolchain to build. |
| Windows | x64. Install the Visual Studio C++ build tools and a Windows SDK to build. |
| Linux | x64 with an X11 or Wayland session and a working Vulkan driver. |

The scanner uses the operating system's `ping` utility on all three platforms. It also uses `arp` when the local neighbor cache does not supply a MAC address. Run the application as a regular user with permission to send ICMP echo requests.

For Ubuntu 24.04, install these Linux build packages.

```sh
sudo apt-get install build-essential cmake clang libclang-dev pkg-config \
  libasound2-dev libfontconfig1-dev libfreetype6-dev libx11-dev libxcb1-dev \
  libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libvulkan-dev libssl-dev \
  iputils-ping net-tools
```

## Build and run

Install Rust with rustup. Cargo uses the version in [rust-toolchain.toml](rust-toolchain.toml).

```sh
cargo run --locked
cargo build --locked --release
```

The release executable is in `target/release`. The macOS CI job also assembles a universal `pistonscan.app` with Intel and Apple silicon binaries.

## Contributing and support

Read [the contribution guide](CONTRIBUTING.md) to set up the Git hooks and run checks. Use [the support guide](SUPPORT.md) for questions and issues.
