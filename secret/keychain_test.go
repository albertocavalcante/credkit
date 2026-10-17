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
		[]byte("b64:c2VjcmV0"),
		{0, 0xff, 0x80, 0x0a},
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
	if len(args) > 0 && args[0] == "find-generic-password" && !slices.Contains(args, "-w") && mode != "put" && mode != "put-silent-failure" {
		kind := encodedKind
		if strings.HasPrefix(mode, "get-legacy") {
			kind = "application password"
		}
		_, _ = fmt.Fprintf(os.Stdout, "    \"desc\"<blob>=\"%s\"\n", kind)
		os.Exit(0)
	}
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
			want := `add-generic-password -a "client-secret" -s "meliboot" -D ` + encodedKind + ` -U -w ` + helperEncoded + "\n"
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
			if slices.Contains(args, "-w") {
				_, _ = os.Stdout.WriteString(helperEncoded + "\n")
			} else {
				_, _ = fmt.Fprintf(os.Stdout, "    \"desc\"<blob>=\"%s\"\n", encodedKind)
			}
		default:
			os.Exit(4)
		}
	case "get":
		_, _ = os.Stdout.WriteString(helperEncoded + "\n")
	case "get-corrupt-marked", "get-legacy-corrupt":
		_, _ = os.Stdout.WriteString("b64:!!!\n")
	case "get-unprefixed-marked":
		_, _ = os.Stdout.WriteString("literal\n")
	case "get-legacy-prefix":
		_, _ = os.Stdout.WriteString("b64:c2VjcmV0\n")
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

func TestUnmarkedPrefixRequiresExplicitEncodingPolicy(t *testing.T) {
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "get-legacy-prefix")
	cases := []struct {
		name    string
		policy  LegacyEncoding
		want    string
		wantErr bool
	}{
		{"ambiguous", LegacyRejectAmbiguous, "", true},
		{"literal", LegacyPlain, "b64:c2VjcmV0", false},
		{"encoded", LegacyBase64, "secret", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand, LegacyEncoding: tc.policy}
			got, err := backend.Get(t.Context(), Key{Service: "test", Account: "legacy"})
			if tc.wantErr {
				if !errors.Is(err, ErrAmbiguousEncoding) {
					t.Fatalf("got %q %v, want ambiguity error", got, err)
				}
			} else if err != nil || string(got) != tc.want {
				t.Fatalf("got %q %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestKeychainCorruptMarkedValuesFail(t *testing.T) {
	for _, mode := range []string{"get-corrupt-marked", "get-unprefixed-marked", "get-legacy-corrupt"} {
		t.Setenv("CREDKIT_KEYCHAIN_HELPER", mode)
		s := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand, LegacyEncoding: LegacyBase64}
		if _, err := s.Get(t.Context(), Key{Service: "test", Account: "corrupt"}); err == nil {
			t.Errorf("accepted mode %s", mode)
		}
	}
}

func TestKeychainLegacyMigrationRealSecurity(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("CREDKIT_SKIP_REAL_KEYCHAIN") != "" {
		t.Skip("native Keychain test unavailable or explicitly skipped")
	}
	for _, tc := range []struct {
		name   string
		policy LegacyEncoding
		want   string
	}{
		{"literal", LegacyPlain, "b64:c2VjcmV0"}, {"encoded", LegacyBase64, "secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := Key{Service: fmt.Sprintf("credkit-legacy-test-%d", os.Getpid()), Account: tc.name}
			backend := KeychainStore{}
			t.Cleanup(func() { _ = backend.Delete(context.Background(), key) })
			input := "add-generic-password -a " + quoteArg(key.Account) + " -s " + quoteArg(key.Service) + " -U -w b64:c2VjcmV0\n"
			if _, err := backend.run(t.Context(), []byte(input), "-i"); err != nil {
				t.Fatal(err)
			}
			if _, err := backend.Get(t.Context(), key); !errors.Is(err, ErrAmbiguousEncoding) {
				t.Fatalf("unmarked prefix should be ambiguous: %v", err)
			}
			legacy := KeychainStore{LegacyEncoding: tc.policy}
			got, err := legacy.Get(t.Context(), key)
			if err != nil || string(got) != tc.want {
				t.Fatalf("legacy decode=%q %v", got, err)
			}
			if err := backend.Put(t.Context(), key, got); err != nil {
				t.Fatal(err)
			}
			got, err = backend.Get(t.Context(), key)
			if err != nil || string(got) != tc.want {
				t.Fatalf("migrated decode=%q %v", got, err)
			}
		})
	}
}

func TestEncodedKindUsesMetadataRatherThanPasswordPrefix(t *testing.T) {
	cases := []struct {
		metadata string
		want     bool
	}{
		{`    "desc"<blob>="credkit.base64.v1"`, true},
		{`    "desc"<blob>="application password"`, false},
		{`    "acct"<blob>="credkit.base64.v1"`, false},
		{`b64:c2VjcmV0`, false},
	}
	for _, tc := range cases {
		if got := hasEncodedKind([]byte(tc.metadata)); got != tc.want {
			t.Errorf("metadata %q -> %v, want %v", tc.metadata, got, tc.want)
		}
	}
}
