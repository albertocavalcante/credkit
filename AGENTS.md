# credkit – Agent Guidelines

## Project Overview

credkit (`github.com/albertocavalcante/credkit`) is a shared Go library of credential management primitives used by sonar-cli, flare, and cofre. It is not a standalone CLI — it is imported as a library by other tools.

## Package Structure

| Package | One-line description |
|---------|----------------------|
| `store` | Secure file I/O with XDG Base Directory compliance (0600/0700 permissions) |
| `resolve` | Configurable credential resolution chain (flag > env > profile > prompt) |
| `profile` | Multi-profile CRUD with JSON storage and credential management |
| `session` | TTL-based session caching for vault/provider keys |
| `token` | Token ledger for expiry monitoring and rotation planning |
| `audit` | Append-only JSON-lines audit log for credential operations |
| `sts` | STS Provider interface, atomic token rotation, health checks |

## Conventions

### Language and Dependencies
- Go 1.26; module path `github.com/albertocavalcante/credkit`
- **Stdlib-only** — the only external dependency is `golang.org/x/term` for masked terminal input
- Do not introduce other external dependencies without strong justification

### Error Handling
- Use `errors.New(...)` for static error strings (not `fmt.Errorf` with no `%w`)
- Use `errors.Is(err, sentinel)` for error checks, not string comparison
- Wrap errors with `fmt.Errorf("...: %w", err)` when adding context

### Sorting
- Use `slices.SortFunc` (stdlib, Go 1.21+) for custom sort logic — do not use `sort.Slice`

### File Permissions
- Files: `0600` (owner read/write only)
- Directories: `0700` (owner read/write/execute only)
- Never create credential files with broader permissions

### Import Ordering
Imports must be grouped in this order (goimports-compatible):
1. Standard library
2. credkit internal packages (`github.com/albertocavalcante/credkit/...`)
3. External dependencies (currently only `golang.org/x/term`)

## Adding a New Package

1. Create the directory: `mkdir <pkgname>/`
2. Add `<pkgname>/<pkgname>.go` with `package <pkgname>` and a package doc comment
3. Write tests first — see Testing Patterns below
4. Update the Packages table in `README.md`
5. Run `go build ./...` and `go vet ./...` before committing

## Testing Patterns

- Use `t.TempDir()` for any test that writes files — never hardcode paths
- Prefer **table-driven tests** with a `[]struct{ name, input, want }` slice and `t.Run(tc.name, ...)`
- Mock HTTP calls via `httptest.NewServer` — never hit real APIs in unit tests
- Test files live alongside the package (`<pkgname>/<pkgname>_test.go`)
- Use `package <pkgname>_test` (black-box) unless white-box access is needed

Example table-driven skeleton:
```go
func TestFoo(t *testing.T) {
    cases := []struct {
        name  string
        input string
        want  string
    }{
        {"empty", "", ""},
        {"basic", "x", "x"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got := Foo(tc.input)
            if got != tc.want {
                t.Errorf("Foo(%q) = %q, want %q", tc.input, got, tc.want)
            }
        })
    }
}
```

## Build and Test

```bash
go build ./...        # compile all packages
go test ./...         # run all tests
go vet ./...          # static analysis
just test             # preferred: uses gotestsum for readable output
just lint             # golangci-lint
just ci               # full CI gate: build + test + lint + vet + fmt-check
```
