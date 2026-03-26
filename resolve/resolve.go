// Package resolve provides a configurable credential resolution chain.
//
// Each tool builds its own chain with provider-specific steps.
// The chain tries steps in order and returns the first match.
package resolve

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNoCredential is returned when no step in the chain resolves a credential.
var ErrNoCredential = errors.New("no credential found")

// Step is a single source in the resolution chain.
type Step struct {
	// Name identifies this step (e.g., "flag", "env:SONAR_TOKEN", "profile", "prompt:secure").
	Name string
	// Resolve returns the credential value and true if found, or ("", false) to skip.
	Resolve func() (string, bool)
}

// Result holds a resolved credential and which step provided it.
type Result struct {
	Value  string
	Source string
}

// Chain resolves credentials by trying steps in priority order.
type Chain struct {
	Steps []Step
}

// Resolve tries each step in order and returns the first match.
func (c *Chain) Resolve() (*Result, error) {
	for _, s := range c.Steps {
		if v, ok := s.Resolve(); ok && v != "" {
			return &Result{Value: v, Source: s.Name}, nil
		}
	}
	return nil, ErrNoCredential
}

// FlagStep returns a step that resolves from a CLI flag value.
func FlagStep(value string) Step {
	return Step{
		Name: "flag",
		Resolve: func() (string, bool) {
			return value, value != ""
		},
	}
}

// EnvStep returns a step that resolves from environment variables.
// It tries each name in order and returns the first non-empty value.
func EnvStep(names ...string) Step {
	return Step{
		Name: "env:" + strings.Join(names, ","),
		Resolve: func() (string, bool) {
			for _, name := range names {
				if v := os.Getenv(name); v != "" {
					return v, true
				}
			}
			return "", false
		},
	}
}

// FileStep returns a step that resolves from a file's contents.
func FileStep(name, path string) Step {
	return Step{
		Name: name,
		Resolve: func() (string, bool) {
			data, err := os.ReadFile(path) //nolint:gosec // path from FileStep constructor, not user input
			if err != nil {
				return "", false
			}
			v := strings.TrimSpace(string(data))
			return v, v != ""
		},
	}
}

// FuncStep returns a step backed by an arbitrary function.
// Use this for profile-based lookups or other custom resolution logic.
func FuncStep(name string, fn func() (string, bool)) Step {
	return Step{Name: name, Resolve: fn}
}

// terminal abstracts terminal detection and password reading for testability.
type terminal struct {
	fd           int
	isTerminal   func(fd int) bool
	readPassword func(fd int) ([]byte, error)
	reader       io.Reader
	writer       io.Writer
}

func defaultTerminal() terminal {
	return terminal{
		fd:           int(os.Stdin.Fd()),
		isTerminal:   term.IsTerminal,
		readPassword: term.ReadPassword,
		reader:       os.Stdin,
		writer:       os.Stdout,
	}
}

// PromptStep returns a step that prompts the user for input via the terminal.
// It is skipped when stdin is not a terminal (e.g., in CI/CD pipelines).
// Input is masked (not echoed) for security.
func PromptStep(prompt string) Step {
	return promptStepWith(prompt, defaultTerminal())
}

func promptStepWith(prompt string, t terminal) Step {
	return Step{
		Name: "prompt:secure",
		Resolve: func() (string, bool) {
			if !t.isTerminal(t.fd) {
				return "", false
			}
			_, _ = fmt.Fprint(t.writer, prompt)
			password, err := t.readPassword(t.fd)
			_, _ = fmt.Fprintln(t.writer)
			if err != nil {
				return "", false
			}
			v := strings.TrimSpace(string(password))
			return v, v != ""
		},
	}
}

// PromptPlainStep returns a step that prompts for non-sensitive input.
// Input is echoed to the terminal. Skipped when stdin is not a terminal.
func PromptPlainStep(prompt string) Step {
	return promptPlainStepWith(prompt, defaultTerminal())
}

func promptPlainStepWith(prompt string, t terminal) Step {
	return Step{
		Name: "prompt:plain",
		Resolve: func() (string, bool) {
			if !t.isTerminal(t.fd) {
				return "", false
			}
			_, _ = fmt.Fprint(t.writer, prompt)
			reader := bufio.NewReader(t.reader)
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", false
			}
			v := strings.TrimSpace(line)
			return v, v != ""
		},
	}
}
