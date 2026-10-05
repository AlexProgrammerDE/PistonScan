# Contribute to PistonScan

Contributions can fix behavior, improve documentation, or add focused tests.

## Before you start

Read [the support guide](SUPPORT.md) for questions and issue routing.
Search existing issues and pull requests. Discuss larger API, architecture, or dependency changes before implementation.

Work from `main` and target that branch in your pull request.
Keep each change focused. Avoid unrelated formatting and dependency updates.

## Prepare a checkout

Use the Go version/toolchain from `go.mod`, Wails v2, and the Bun version in `frontend/package.json`. Install Wails platform prerequisites.

```bash
bun install --cwd frontend --frozen-lockfile
```

Run the commands below from the repository root unless a command names another directory.
On Windows, use `gradlew.bat` in place of `./gradlew` for Gradle commands.

## Repository layout

- `internal/`: network discovery and scanner logic.
- `app.go`, `main.go`: Wails application integration.
- `frontend/`: React interface.
- `PROTOCOLS.md`, `DISCOVERY_METHODS.md`: discovery reference.

## Verify your change

```bash
go test ./internal/...
bun run --cwd frontend build
```

Read [AGENTS.md](AGENTS.md). Use `wails doctor` to diagnose missing native dependencies. Use `wails dev` for full application development and `wails build` for a production package. Let Wails generate bindings. Keep probes cancellable and bounded. Use local fixtures or a network you control for discovery checks. Verify changed behavior on the affected operating systems.

Run the relevant checks before review. State the command and result in the pull request.
If a check cannot run, explain the missing dependency or service. Do not claim it passed.
Keep generated artifacts consistent with their source and review their diff.

## Style and documentation

Follow the existing code conventions and repository formatter. Keep commit hooks enabled.
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
