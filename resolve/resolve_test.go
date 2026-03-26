package resolve_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertocavalcante/credkit/resolve"
)

func TestChain_FlagWins(t *testing.T) {
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FlagStep("from-flag"),
			resolve.FuncStep("fallback", func() (string, bool) { return "nope", true }),
		},
	}
	result, err := chain.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "from-flag" {
		t.Fatalf("value = %q, want %q", result.Value, "from-flag")
	}
	if result.Source != "flag" {
		t.Fatalf("source = %q, want %q", result.Source, "flag")
	}
}

func TestChain_SkipsEmptyFlag(t *testing.T) {
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FlagStep(""),
			resolve.FuncStep("custom", func() (string, bool) { return "found", true }),
		},
	}
	result, err := chain.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "found" {
		t.Fatalf("value = %q, want %q", result.Value, "found")
	}
	if result.Source != "custom" {
		t.Fatalf("source = %q, want %q", result.Source, "custom")
	}
}

func TestChain_EnvStep(t *testing.T) {
	t.Setenv("CREDKIT_A", "")
	t.Setenv("CREDKIT_B", "val-b")

	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.EnvStep("CREDKIT_A", "CREDKIT_B"),
		},
	}
	result, err := chain.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "val-b" {
		t.Fatalf("value = %q, want %q", result.Value, "val-b")
	}
	if result.Source != "env:CREDKIT_A,CREDKIT_B" {
		t.Fatalf("source = %q", result.Source)
	}
}

func TestChain_EnvStep_AllEmpty(t *testing.T) {
	t.Setenv("CREDKIT_X", "")
	t.Setenv("CREDKIT_Y", "")

	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.EnvStep("CREDKIT_X", "CREDKIT_Y"),
		},
	}
	_, err := chain.Resolve()
	if !errors.Is(err, resolve.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestChain_NoMatch(t *testing.T) {
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FlagStep(""),
			resolve.EnvStep("CREDKIT_NEVER_SET_99999"),
		},
	}
	_, err := chain.Resolve()
	if !errors.Is(err, resolve.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestChain_EmptySteps(t *testing.T) {
	chain := &resolve.Chain{}
	_, err := chain.Resolve()
	if !errors.Is(err, resolve.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestFileStep_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("my-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FileStep("profile", path),
		},
	}
	result, err := chain.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "my-token" {
		t.Fatalf("value = %q, want %q", result.Value, "my-token")
	}
	if result.Source != "profile" {
		t.Fatalf("source = %q, want %q", result.Source, "profile")
	}
}

func TestFileStep_Missing(t *testing.T) {
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FileStep("file", "/nonexistent/path"),
		},
	}
	_, err := chain.Resolve()
	if !errors.Is(err, resolve.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestFileStep_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FileStep("file", path),
		},
	}
	_, err := chain.Resolve()
	if !errors.Is(err, resolve.ErrNoCredential) {
		t.Fatalf("empty file should not resolve, err = %v", err)
	}
}

func TestFuncStep(t *testing.T) {
	called := false
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FuncStep("vault", func() (string, bool) {
				called = true
				return "vault-secret", true
			}),
		},
	}
	result, err := chain.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("func was not called")
	}
	if result.Value != "vault-secret" {
		t.Fatalf("value = %q", result.Value)
	}
}

func TestFuncStep_ReturnsFalse(t *testing.T) {
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FuncStep("nope", func() (string, bool) { return "", false }),
		},
	}
	_, err := chain.Resolve()
	if !errors.Is(err, resolve.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestPromptStep_SkipsNonTerminal(t *testing.T) {
	// In test, stdin is not a terminal — PromptStep should skip.
	step := resolve.PromptStep("Token: ")
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("expected skip in non-terminal, got %q/%v", v, ok)
	}
	if step.Name != "prompt:secure" {
		t.Fatalf("name = %q, want %q", step.Name, "prompt:secure")
	}
}

func TestPromptPlainStep_SkipsNonTerminal(t *testing.T) {
	step := resolve.PromptPlainStep("Email: ")
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("expected skip in non-terminal, got %q/%v", v, ok)
	}
	if step.Name != "prompt:plain" {
		t.Fatalf("name = %q, want %q", step.Name, "prompt:plain")
	}
}

func TestChain_PriorityOrder(t *testing.T) {
	// Verify that earlier steps win over later ones.
	t.Setenv("CREDKIT_PRI", "from-env")
	chain := &resolve.Chain{
		Steps: []resolve.Step{
			resolve.FlagStep(""),           // empty, skip
			resolve.EnvStep("CREDKIT_PRI"), // hits
			resolve.FuncStep("late", func() (string, bool) { return "late-val", true }),
		},
	}
	result, err := chain.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "from-env" {
		t.Fatalf("value = %q, want env value", result.Value)
	}
}
