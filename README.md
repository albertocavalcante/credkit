# credkit

[![CI](https://github.com/albertocavalcante/credkit/actions/workflows/ci.yml/badge.svg)](https://github.com/albertocavalcante/credkit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)

Shared credential management primitives for Go CLI tools.

credkit provides the building blocks for multi-profile credential storage, resolution chains, session caching, token lifecycle tracking, and audit logging. It is designed to be imported by standalone CLI tools that each manage their own provider-specific authentication.

## Packages

| Package | Purpose |
|---------|---------|
| [`store`](store/) | Secure file I/O with XDG Base Directory compliance (0600/0700 permissions) |
| [`resolve`](resolve/) | Configurable credential resolution chain (flag > env > profile > prompt) |
| [`profile`](profile/) | Multi-profile CRUD with JSON storage and credential management |
| [`session`](session/) | TTL-based session caching for vault/provider keys |
| [`token`](token/) | Token ledger for expiry monitoring and rotation planning |
| [`audit`](audit/) | Append-only JSON-lines audit log for credential operations |

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

## Design Principles

- **Stdlib-first**: Only external dependency is `golang.org/x/term` for masked terminal input
- **XDG-compliant**: Respects `$XDG_CONFIG_HOME`, falls back to `~/.config/<app>`
- **Secure by default**: Files at 0600, directories at 0700
- **Standalone-friendly**: Each CLI tool imports only what it needs, no orchestrator dependency
- **Thread-safe**: Ledger and audit logger are safe for concurrent use

## License

MIT
