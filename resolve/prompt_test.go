package resolve

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func fakeTerminal(input string) terminal {
	return terminal{
		fd:         42,
		isTerminal: func(fd int) bool { return true },
		readPassword: func(fd int) ([]byte, error) {
			return []byte(input), nil
		},
		reader: strings.NewReader(input + "\n"),
		writer: io.Discard,
	}
}

func nonTerminal() terminal {
	return terminal{
		fd:         42,
		isTerminal: func(fd int) bool { return false },
		reader:     strings.NewReader(""),
		writer:     io.Discard,
	}
}

func TestPromptStepWith_Success(t *testing.T) {
	step := promptStepWith("Token: ", fakeTerminal("my-secret"))
	v, ok := step.Resolve()
	if !ok || v != "my-secret" {
		t.Fatalf("got %q/%v, want my-secret/true", v, ok)
	}
}

func TestPromptStepWith_EmptyInput(t *testing.T) {
	step := promptStepWith("Token: ", fakeTerminal(""))
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("empty input should return false, got %q/%v", v, ok)
	}
}

func TestPromptStepWith_WhitespaceOnly(t *testing.T) {
	step := promptStepWith("Token: ", fakeTerminal("   "))
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("whitespace should return false, got %q/%v", v, ok)
	}
}

func TestPromptStepWith_NonTerminal(t *testing.T) {
	step := promptStepWith("Token: ", nonTerminal())
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("non-terminal should skip, got %q/%v", v, ok)
	}
}

func TestPromptStepWith_ReadError(t *testing.T) {
	term := fakeTerminal("")
	term.readPassword = func(fd int) ([]byte, error) {
		return nil, errors.New("read failed")
	}
	step := promptStepWith("Token: ", term)
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("read error should return false, got %q/%v", v, ok)
	}
}

func TestPromptStepWith_WritesPrompt(t *testing.T) {
	var buf bytes.Buffer
	term := fakeTerminal("val")
	term.writer = &buf
	promptStepWith("Enter: ", term).Resolve()
	if !strings.Contains(buf.String(), "Enter: ") {
		t.Fatalf("prompt not written: %q", buf.String())
	}
}

func TestPromptPlainStepWith_Success(t *testing.T) {
	step := promptPlainStepWith("Email: ", fakeTerminal("user@test.com"))
	v, ok := step.Resolve()
	if !ok || v != "user@test.com" {
		t.Fatalf("got %q/%v, want user@test.com/true", v, ok)
	}
}

func TestPromptPlainStepWith_EmptyInput(t *testing.T) {
	term := fakeTerminal("")
	term.reader = strings.NewReader("\n")
	step := promptPlainStepWith("Email: ", term)
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("empty should return false, got %q/%v", v, ok)
	}
}

func TestPromptPlainStepWith_NonTerminal(t *testing.T) {
	step := promptPlainStepWith("Email: ", nonTerminal())
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("non-terminal should skip, got %q/%v", v, ok)
	}
}

func TestPromptPlainStepWith_ReadError(t *testing.T) {
	term := fakeTerminal("")
	term.reader = &errReader{}
	step := promptPlainStepWith("Email: ", term)
	v, ok := step.Resolve()
	if ok || v != "" {
		t.Fatalf("read error should return false, got %q/%v", v, ok)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
