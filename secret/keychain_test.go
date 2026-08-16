package secret

import (
	"context"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestKeychainStorePutKeepsSecretOutOfArguments(t *testing.T) {
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "put")
	backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand}
	if err := backend.Put(t.Context(), Key{Service: "meliboot", Account: "client-secret"}, []byte("s3cret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
}

func TestKeychainStoreGetAndDelete(t *testing.T) {
	backend := KeychainStore{ExecutablePath: os.Args[0], CommandContext: keychainHelperCommand}
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "get")
	value, err := backend.Get(t.Context(), Key{Service: "meliboot", Account: "client-secret"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got, want := string(value), "s3cret"; got != want {
		t.Fatalf("Get() = %q, want %q", got, want)
	}
	t.Setenv("CREDKIT_KEYCHAIN_HELPER", "delete")
	if err := backend.Delete(t.Context(), Key{Service: "meliboot", Account: "client-secret"}); err != nil {
		t.Fatalf("Delete() error = %v", err)
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
		if strings.Contains(arg, "s3cret") {
			os.Exit(3)
		}
	}
	switch mode {
	case "put":
		if len(args) == 0 || args[0] != "add-generic-password" || args[len(args)-1] != "-w" {
			os.Exit(4)
		}
		input, err := io.ReadAll(os.Stdin)
		if err != nil || string(input) != "s3cret\n" {
			os.Exit(5)
		}
	case "get":
		_, _ = os.Stdout.WriteString("s3cret\n")
	case "delete":
		if len(args) == 0 || args[0] != "delete-generic-password" {
			os.Exit(6)
		}
	default:
		os.Exit(7)
	}
	os.Exit(0)
}
