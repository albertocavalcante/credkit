package secret

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const helperSecret = "s3cret"

var helperEncoded = "b64:" + base64.StdEncoding.EncodeToString([]byte(helperSecret))

func TestKeychainStorePutUsesInteractiveStdinNotArguments(t *testing.T) {
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "put")
	t.Setenv("CREDKIT_KEYCHAIN_STATE", filepath.Join(t.TempDir(), "state"))
	backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand}
	if err := backend.Put(t.Context(), Key{Service: "meliboot", Account: "client-secret"}, []byte(helperSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
}

func TestKeychainStorePutFailsWhenReadBackDiffers(t *testing.T) {
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "put-silent-failure")
	t.Setenv("CREDKIT_KEYCHAIN_STATE", filepath.Join(t.TempDir(), "state"))
	backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand}
	err := backend.Put(t.Context(), Key{Service: "meliboot", Account: "client-secret"}, []byte(helperSecret))
	if err == nil {
		t.Fatal("Put() succeeded although the item was not stored")
	}
	if strings.Contains(err.Error(), helperSecret) {
		t.Fatalf("error leaks the secret: %v", err)
	}
}

func TestKeychainStoreGetAndDelete(t *testing.T) {
	backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand}
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "get")
	value, err := backend.Get(t.Context(), Key{Service: "meliboot", Account: "client-secret"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got, want := string(value), helperSecret; got != want {
		t.Fatalf("Get() = %q, want %q", got, want)
	}
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "delete")
	if err := backend.Delete(t.Context(), Key{Service: "meliboot", Account: "client-secret"}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestKeychainStoreGetReadsLegacyPlainText(t *testing.T) {
	backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand}
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "get-legacy")
	value, err := backend.Get(t.Context(), Key{Service: "meliboot", Account: "client-secret"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(value) != helperSecret {
		t.Fatalf("Get() = %q, want %q", value, helperSecret)
	}
}

func TestQuoteArg(t *testing.T) {
	cases := map[string]string{
		`plain`:   `"plain"`,
		`a b`:     `"a b"`,
		`say "x"`: `"say \"x\""`,
		`back\sl`: `"back\\sl"`,
	}
	for in, want := range cases {
		if got := quoteArg(in); got != want {
			t.Errorf("quoteArg(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestKeychainStoreRealSecurity is the oracle: it drives the real macOS
// `security` tool. The mocked helper above can only prove what we believe
// `security` does; this proves what it does (an earlier mock-only suite passed
// while the real tool prompted on the terminal instead of reading stdin).
func TestKeychainStoreRealSecurity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS keychain only")
	}
	if os.Getenv("CREDKIT_SKIP_REAL_KEYCHAIN") != "" {
		t.Skip("CREDKIT_SKIP_REAL_KEYCHAIN set")
	}
	backend := KeychainStore{}
	key := Key{Service: fmt.Sprintf("credkit-test-%d", os.Getpid()), Account: `acct with "quote" and space`}
	t.Cleanup(func() { _ = backend.Delete(context.Background(), key) })

	values := [][]byte{
		[]byte("simple"),
		[]byte(`{"refresh_token":"1//0abc-_/+=","email":"x@y.z","q":"\"quoted\" \\ back"}`),
		[]byte("multi\nline\ttab ünïcode ✓"),
		[]byte("-w looks-like-a-flag"),
	}
	for _, want := range values {
		// Closed stdin and no controlling-terminal reliance: a prompt would hang or fail.
		if err := backend.Put(t.Context(), key, want); err != nil {
			t.Fatalf("Put(%q) error = %v", want, err)
		}
		got, err := backend.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip = %q, want %q", got, want)
		}
	}
	if err := backend.Delete(t.Context(), key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := backend.Get(t.Context(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after Delete error = %v, want ErrNotFound", err)
	}
}

func keychainHelperCommand(ctx context.Context, _ string, args ...string) *exec.Cmd {
	cmdArgs := []string{"-test.run=TestKeychainHelperProcess", "--"}
	cmdArgs = append(cmdArgs, args...)
	return exec.CommandContext(ctx, os.Args[0], cmdArgs...)
}

func TestKeychainHelperProcess(t *testing.T) {
	mode := os.Getenv("CREDKIT_KEYCHAIN_HELPER")
	if mode == "" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		os.Exit(2)
	}
	args := os.Args[separator+1:]
	for _, arg := range args {
		if strings.Contains(arg, helperSecret) || strings.Contains(arg, helperEncoded) {
			os.Exit(3)
		}
	}
	switch mode {
	case "put", "put-silent-failure":
		// `security -i`: the only argument is -i, commands arrive on stdin.
		if len(args) == 0 {
			os.Exit(0) // a later call (read-back) handled below
		}
		switch args[0] {
		case "-i":
			input, err := io.ReadAll(os.Stdin)
			want := `add-generic-password -a "client-secret" -s "meliboot" -U -w ` + helperEncoded + "\n"
			if err != nil || string(input) != want {
				os.Exit(5)
			}
			if mode == "put-silent-failure" {
				os.Exit(0) // exits 0 without storing, like the real tool can
			}
			if err := os.WriteFile(os.Getenv("CREDKIT_KEYCHAIN_STATE"), []byte("x"), 0o600); err != nil {
				os.Exit(8)
			}
		case "find-generic-password":
			if _, err := os.Stat(os.Getenv("CREDKIT_KEYCHAIN_STATE")); err != nil {
				os.Exit(44)
			}
			_, _ = os.Stdout.WriteString(helperEncoded + "\n")
		default:
			os.Exit(4)
		}
	case "get":
		_, _ = os.Stdout.WriteString(helperEncoded + "\n")
	case "get-legacy":
		_, _ = os.Stdout.WriteString(helperSecret + "\n")
	case "delete":
		if len(args) == 0 || args[0] != "delete-generic-password" {
			os.Exit(6)
		}
	default:
		os.Exit(7)
	}
	os.Exit(0)
}
