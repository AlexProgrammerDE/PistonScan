# Agent Guidelines

## Developing the Application
- Run the application in development mode with `wails dev` from the project root. This will build and run the app, bind Go code to the frontend, watch for Go file changes, and serve the app over a browser so you can use browser extensions and call Go code from the console.
- While in dev mode, the CLI automatically updates `go.mod` to match the CLI version, recompiles the app on Go file changes, reloads assets on change, and generates JavaScript/TypeScript bindings for Go methods and structs.
- Use the `wails dev` flags when needed:
  - `-browser` to automatically open the dev server at `http://localhost:34115`.
  - `-assetdir`, `-wailsjsdir`, and `-reloaddirs` to customise asset serving and reload behaviour (you can persist these with `-save`).
  - `-race`, `-ldflags`, `-tags`, or `-compiler` to control compilation behaviour.
  - `-forcebuild` to trigger a rebuild, and `-noreload` to disable automatic reloads.
- Example: `wails dev -assetdir ./frontend/dist -wailsjsdir ./frontend/src -browser` builds and runs the app, generates bindings into `frontend/src`, watches `frontend/dist` for reloads, and launches the browser.

## Build & Release
- Use `wails build` for production binaries. Important flags include `-clean` (clear `build/bin`), `-debug` or `-devtools` (debug tooling), `-platform` (cross-compilation), `-race`, `-tags`, `-trimpath`, `-o` (output filename), `-obfuscated`/`-garbleargs` (garble integration), and `-upx`/`-upxflags` (binary compression). Combine flags as required for your release pipeline.
- Example: `wails build -clean -o myproject.exe` cleans previous builds and outputs a Windows binary named `myproject.exe`.
- Remember that enabling devtools in production may violate Mac App Store requirements and that UPX may not work on Apple Silicon.

## CLI Reference
- General CLI usage follows `wails <command> <flags>`.
- `wails init` scaffolds projects. Key flags: `-n` (name, required), `-d` (directory), `-g` (init git), `-l` (list templates), `-t` (template name or GitHub URL), `-ide` (generate IDE files), `-f` (force). Example: `wails init -n test -d mytestproject -g -ide vscode -q`.
- Remote templates are supported via GitHub URLs (for example `wails init -n test -t https://github.com/leaanthony/testtemplate[@v1.0.0]`). Inspect third-party templates (`package.json`, `wails.json`) before use.
- `wails generate template` scaffolds custom templates (`-name`, `-frontend`).
- `wails generate module` regenerates the `wailsjs` directory, with optional compiler and build tags.
- `wails doctor` checks system readiness; run it if you suspect environment issues.
- `wails update` upgrades the CLI (`-pre` for pre-release, `-version` for specific versions) and `wails version` prints the current version.

## Additional Tips
- When building on macOS, releases bundle with `Info.plist`; development builds use `build/darwin/Info.dev.plist`.
- Set minimum macOS versions with `CGO_CFLAGS`/`CGO_LDFLAGS` (for example `CGO_CFLAGS=-mmacosx-version-min=10.15.0`).
- UPX-compressed binaries may trigger antivirus false positives on Windows.
- Supported build targets include macOS (`darwin`, `darwin/amd64`, `darwin/arm64`, `darwin/universal`), Windows (`windows`, `windows/amd64`, `windows/arm64`), and Linux (`linux`, `linux/amd64`, `linux/arm64`).
