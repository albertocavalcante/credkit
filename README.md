# credkit

The name **credkit** is provisional; the current module path is unchanged.

[![CI](https://github.com/albertocavalcante/credkit/actions/workflows/ci.yml/badge.svg)](https://github.com/albertocavalcante/credkit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)

Shared credential management primitives for Go CLI tools.

credkit provides the building blocks for multi-profile credential storage, resolution chains, session caching, token lifecycle tracking, and audit logging. It is designed to be imported by standalone CLI tools that each manage their own provider-specific authentication.

## Packages

| Package | Purpose |
|---------|---------|
| [`store`](store/) | Secure file I/O with XDG Base Directory compliance (0600/0700 permissions) |
| [`secret`](secret/) | Opaque secret storage backed by the macOS Keychain or secure files |
| [`resolve`](resolve/) | Configurable credential resolution chain (flag > env > profile > prompt) |
| [`profile`](profile/) | Multi-profile CRUD with JSON storage and credential management |
| [`session`](session/) | TTL-based session caching for vault/provider keys |
| [`token`](token/) | Token ledger for expiry monitoring and rotation planning |
| [`audit`](audit/) | Append-only JSON-lines audit log for credential operations |
| [`oauth`](oauth/) | OAuth authorization-code, PKCE, callback, and refresh primitives |
| [`sts`](sts/) | STS Provider interface, recoverable token rotation, health checks |

## Install

```
go get github.com/albertocavalcante/credkit
```

## Usage

### Credential Resolution Chain

```go
chain := &resolve.Chain{
    Steps: []resolve.Step{
        resolve.FlagStep(flagToken),
        resolve.EnvStep("SONAR_TOKEN", "SONARCLOUD_TOKEN"),
        resolve.FuncStep("profile", func() (string, bool) {
            data, err := profileMgr.LoadCredential(activeProfile)
            if err != nil {
                return "", false
            }
            return strings.TrimSpace(string(data)), true
        }),
        resolve.PromptStep("Token: "),
    },
}

result, err := chain.Resolve()
// result.Value = "the-token"
// result.Source = "env:SONAR_TOKEN,SONARCLOUD_TOKEN"
```

### Profile Management

```go
mgr, _ := profile.NewManager("myapp")

mgr.Save("work", &profile.Profile{
    Fields: map[string]string{"org": "acme", "zone": "example.com"},
})

mgr.SaveCredential("work", []byte(`{"type":"token","value":"abc"}`))
mgr.SetActive("work")

p, _ := mgr.Load("work")
cred, _ := mgr.LoadCredential("work")
```

### Session Caching

```go
mgr := session.NewManager(configDir, 4*time.Hour)

// Save after successful vault unlock
mgr.Save("bitwarden", sessionKey)

// Resolve with priority: explicit > env > cached
key, _ := mgr.Resolve("bitwarden", "", "COFRE_BW_SESSION", "BW_SESSION")
```

### Token Ledger

```go
ledger := token.NewLedger(filepath.Join(configDir, "tokens.json"))

expires := time.Now().Add(7 * 24 * time.Hour)
ledger.Record(&token.Metadata{
    Provider:  "sonarcloud",
    Name:      "cofre-sonarcloud-myapp-20250216T153042",
    ExpiresAt: &expires,
    Scope:     map[string]string{"project": "myapp"},
    Source:    "cofre",
})

// Find tokens expiring soon
expiring, _ := ledger.Expiring(7 * 24 * time.Hour)
```

### Audit Logging

```go
logger := audit.NewLogger(filepath.Join(configDir, "audit.log"))

logger.Log(audit.Entry{
    Action:   "issue",
    Provider: "sonarcloud",
    TokenName: "cofre-sonarcloud-myapp",
    Success:  true,
    Source:   "cofre",
})

// Query recent events
entries, _ := logger.Query(time.Now().Add(-24*time.Hour), "sonarcloud")
```

### STS Provider & Rotation

```go
// Implement the Provider interface for your service.
type MyProvider struct { /* auth injected at construction */ }

func (p *MyProvider) Name() string { return "myservice" }
func (p *MyProvider) Issue(ctx context.Context, req *sts.IssueRequest) (*sts.Token, error) { ... }
func (p *MyProvider) Revoke(ctx context.Context, tokenID string) error { ... }
func (p *MyProvider) List(ctx context.Context) ([]*sts.Token, error) { ... }
func (p *MyProvider) Validate(ctx context.Context, tokenValue string) error { ... }

// Recoverable rotation: issue new → validate → record → revoke old
result, _ := sts.Rotate(ctx, provider, "old-token-id", &sts.IssueRequest{
    Name:  "rotated-token",
    Scope: map[string]string{"project": "myapp"},
    TTL:   24 * time.Hour,
},
    sts.WithTransition(5 * time.Minute),  // wait before revoking old
    sts.WithLedger(ledger),               // record in token ledger
    sts.WithAudit(auditLogger, "my-cli"), // log to audit trail
)

// Health metadata: classify expiry; unknown tokens have not been validated
report, _ := sts.CheckHealth(ctx, provider, ledger, 7*24*time.Hour)
total, valid, invalid, expired, expiringSoon := report.Counts()
```

## Design Principles

- **Stdlib-first**: Only external dependency is `golang.org/x/term` for masked terminal input
- **XDG-compliant**: Respects `$XDG_CONFIG_HOME`, falls back to `~/.config/<app>`
- **Secure by default**: Files at 0600, directories at 0700
- **Standalone-friendly**: Each CLI tool imports only what it needs, no orchestrator dependency
- **Thread-safe**: Ledger transactions are serialized across instances in this process; each audit logger supports concurrent use

## License

MIT

OAuth token requests refuse redirects and bound decompressed responses to 1 MiB.
Successful responses require a nonempty access token. Public token JSON decoding
replaces prior derived fields and rejects expiry arithmetic overflow.

Use `AuthCodeURLChecked` to receive invalid-configuration errors. Configure
`CallbackOptions.ExpectedState` to reject unrelated callbacks before consuming
the pending login; error callbacks preserve state too. Without that option,
the application must verify state on successful and error redirects.

`sts.Rotate` returns partial progress after issuance even when later work fails.
Inspect the returned replacement and progress flags before retrying; rollback,
ledger and audit failures are reported. A configured ledger records the validated
replacement before old-token revocation. Cleanup after failed validation uses a
fresh context with a five-second timeout. These remote and local steps are not
an atomic transaction.

`sts.CheckHealth` reports ledger metadata rather than provider validation.
Tokens without an expiry warning are in `report.Unknown`, not `report.Valid`.
`Counts` retains its five return values; its total includes Unknown entries,
whose count is available as `len(report.Unknown)`.

Profile, session and file-secret managers treat their configured directory as
the trusted storage root, including an intentional symlink at that root. Managed
descendant directories and files must not be symlinks. Rooted IO uses `os.Root`
and owner-only permissions. Reads and listings never create paths or repair modes;
unsafe permissions return `store.ErrUnsafePath`. Secure existence checks return
false for unsafe paths. Already-private read-only files and directories retain
their modes, including 0400 files and 0500 directories. Removal also requires
already-private parents and never adjusts modes.
The absolute-path store helpers trust their immediate parent. Call the `*At`
functions with an explicit application root to constrain descendant traversal.
Audit appends reject symlinks/nonregular files and repair overly broad file modes.

`token.Ledger.FindByID` now matches provider-native IDs exactly and rejects empty
IDs. Use `FindByName` for the former display-name fallback. This prevents a
name collision from selecting the wrong token.

Profile and session resolution treat only missing files as absent; failed reads
and corrupt cache contents now return errors. Session files include precise
`expires_at` timestamps while old `ttl_seconds` files remain readable. Positive
fractional TTLs retain their precision; negative TTLs expire immediately.

Keychain writes now mark base64 encoding in the item's kind metadata. An
unmarked legacy value beginning with `b64:` returns `secret.ErrAmbiguousEncoding`
by default, because its bytes could be either literal or encoded. For migration,
set `KeychainStore.LegacyEncoding` to `secret.LegacyPlain` or `secret.LegacyBase64`
according to the known old format, read the value, then save it with `Put`. New
marked entries decode consistently regardless of that migration policy.


### Migration examples and storage guarantees

The executable examples cover [rotation recovery](sts/example_test.go),
[unknown health](sts/example_test.go), [exact ID versus name lookup](token/example_test.go),
and [rooted credential IO](store/example_test.go). Run them with
`go test ./sts ./token ./store -run Example`. The [Keychain migration example](secret/example_test.go)
shares its implementation with `TestKeychainLegacyMigrationRealSecurity`, which
executes both known legacy formats using temporary native Keychain items on macOS.
The standalone example is compiled but does not run against a user's credentials.

Ledger read-modify-write transactions share one process-wide mutex, including
independent `Ledger` instances and filesystem aliases. This intentionally also
serializes unrelated ledger files; these metadata operations favor correctness
and simple lock ownership over parallel file IO. Multiple processes must coordinate
externally around the complete transaction. Atomic file replacement alone does not
prevent lost updates from independent processes.

Secure writes sync and close a temporary file before replacing the destination.
Readers on a filesystem with atomic rename observe a complete old or new value.
A failed replacement preserves the previous file and removes its temporary file.
An abrupt process termination can leave an owner-only temporary file; no automatic
recovery or power-loss durability guarantee is provided. In particular, the parent
directory is not synced. Concurrent secure reads can return `store.ErrUnsafePath`
when the destination changes between identity checks; retry the read when replacing
credentials concurrently. Filesystem operations and permission guarantees remain
subject to the host filesystem and operating system.

The pure fuzz targets can be run separately without making network requests or
invoking the Keychain CLI per input:

```sh
go test ./oauth -run '^$' -fuzz '^FuzzTokenUnmarshal$' -fuzztime 30s -parallel 2
go test ./oauth -run '^$' -fuzz '^FuzzAuthCodeURLReservedParameters$' -fuzztime 30s -parallel 2
go test ./secret -run '^$' -fuzz '^FuzzKeychainEncodingMetadata$' -fuzztime 30s -parallel 2
```

Secure reads now reject overly broad existing permissions instead of repairing
them as a side effect. This keeps credential resolution and consumer dry runs
free of permission changes. Provision private directories explicitly before
reading existing data, or repair known paths in a separate authorized migration.
The core `WriteSecure`, `WriteSecureAt`, and `OpenAppendSecure` operations still
repair the paths they manage to 0700 directories and 0600 files. Operations
that first load existing metadata, including ledger mutators, can fail with
`ErrUnsafePath` before writing and require explicit provisioning or migration.
A missing path under an unsafe existing root is reported as unsafe rather than
silently treated as absent.
