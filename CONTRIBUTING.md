# Contribute to PistonScan

Contributions can fix behavior, improve documentation, or add focused tests.

## Before you start

Read [the support guide](SUPPORT.md) for questions and issue routing.
Search existing issues and pull requests. Discuss larger API, architecture, or dependency changes before implementation.

Work from `main` and target that branch in your pull request.
Keep each change focused. Avoid unrelated formatting and dependency updates.

## Prepare a checkout

Install the [platform prerequisites](README.md#platform-requirements), Rust through rustup, and Lefthook. Run `lefthook install` and `lefthook validate`.

Run `cargo run --locked` to open the application.

## Repository layout

- `src/` contains the scanner, snapshot format, and desktop entry point.
- `src/desktop/` contains the results view and file dialogs.
- `assets/oui/` contains the MAC vendor database and its license.

## Verify your change

Follow the commands in [AGENTS.md](AGENTS.md). Use offline fixtures for automated checks. Use a network you control to verify discovery on a supported operating system.

## Style and documentation

Follow the existing code conventions and repository formatter. Format Rust with `cargo fmt --all`. Keep commit hooks enabled.
Add focused tests for changed logic when practical. Avoid tests that only assert source strings.
Update documentation when commands, APIs, configuration, or expected behavior change.
Keep examples small and reproducible. Preserve exact identifiers, commands, and error messages.

## Open a pull request

Explain the problem and resulting behavior. Link related issues without a placeholder issue number.
Identify affected protocols and operating systems. Include screenshots for visible changes.
Include commands and results. State any runtime checks that remain necessary.
Respond to review with a correction or concrete evidence.

Use Conventional Commits: `type(scope): description`, for example `docs(contributing): explain local validation`.
Use a meaningful scope, or omit it. Keep the subject concise and imperative.
Add a body when the reason or compatibility impact is not obvious.

For vulnerabilities, follow [the security reporting instructions](SECURITY.md).
Remove credentials and private data from examples, logs, and screenshots.
