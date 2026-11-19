# Develop PistonScan

PistonScan uses Rust and GPUI. Keep scan logic in the library so tests can run without desktop libraries. Keep native UI code in `src/main.rs` and `src/desktop/`.

- Use `src/manager.rs` for scan scheduling and streamed progress.
- Use the scanner modules in `src/` for discovery, response parsing, and insight scoring.
- Keep JSON snapshots compatible with existing PistonScan exports.
- Bound and cancel network work. Test protocol parsers with offline fixtures.
- Use IPv4 addresses for scan targets. Keep network and broadcast addresses in CIDR expansion.
- Use the BedrockFoundry lint configuration. Keep unsafe code forbidden and Clippy free of warnings.

- Keep the shell and scan events in `src/main.rs`. Keep the toolbar, device list, inspector, settings, and theme in separate desktop modules.
- Put target validation and device filters in `src/desktop/state.rs`. Keep preferences separate from scan snapshots.
- Keep list rows the same height so GPUI can draw only the rows in view. Preserve the selected IP and the top visible host as results arrive.
- Open `tests/fixtures/studio-network.json` to review the device list. In a debug build, set `PISTONSCAN_PREVIEW` to `inspector` or `long-content` to select a fixture device.
- Set `PISTONSCAN_PREVIEW` to `empty`, `scanning`, `paused`, `stopping`, `cancelled`, `no-results`, `error`, or `settings` to review that state. With the fixture open, set `PISTONSCAN_PREVIEW` to `focus` to focus search.
- Set `PISTONSCAN_PREVIEW_MINIMUM=1` to start at the minimum size. Review light and dark mode when changing the layout.

## Build and verify

Install the [platform prerequisites](README.md#platform-requirements) and Lefthook. The minimum macOS version is 10.15.7 on Intel and 11 on Apple silicon.
Install cargo-deny 0.20.2 to run the dependency check locally and in the pre-push hook.

```sh
lefthook install
lefthook validate
cargo run --locked
cargo fmt --all --check
cargo fmt --manifest-path vendor/xattr/Cargo.toml --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo check --locked --no-default-features
cargo deny --locked check
cargo build --locked --release
actionlint
```

If you lack GPUI system libraries, run `cargo test --locked --no-default-features --lib` and report what the linker could not find. Keep Git hooks enabled.
