# Agent Guidelines

- Format Go code with `gofmt` before committing changes.
- Place CLI entry points under `cmd/` and keep reusable logic in packages when functionality is added.
- Favor straightforward standard-library solutions unless there is a clear benefit to add dependencies.
- Keep usage text for commands up to date when modifying CLI behavior.
