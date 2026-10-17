package sts_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/albertocavalcante/credkit/store"
	"github.com/albertocavalcante/credkit/sts"
	"github.com/albertocavalcante/credkit/token"
)

// exampleProvider simulates a remote service whose old-token revocation fails.
type exampleProvider struct{}

func (exampleProvider) Name() string { return "example" }
func (exampleProvider) Issue(context.Context, *sts.IssueRequest) (*sts.Token, error) {
	return &sts.Token{ID: "new-id", Name: "deployment", Value: "synthetic"}, nil
}
func (exampleProvider) Validate(context.Context, string) error { return nil }
func (exampleProvider) Revoke(context.Context, string) error {
	return errors.New("service temporarily unavailable")
}
func (exampleProvider) List(context.Context) ([]*sts.Token, error) { return nil, nil }

func ExampleRotate_recovery() {
	root, err := os.MkdirTemp("", "credkit-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	ledger := token.NewLedger(filepath.Join(root, "tokens.json"))
	result, err := sts.Rotate(context.Background(), exampleProvider{}, "old-id", &sts.IssueRequest{Name: "deployment"}, sts.WithLedger(ledger))
	if err != nil {
		// A failed rotation may already have created a usable replacement.
		// Save it before returning, and reconcile progress before retrying.
		if result != nil && result.New != nil && result.NewValidated && !result.NewRevoked {
			if saveErr := store.WriteSecureAt(root, "credential", []byte(result.New.Value)); saveErr != nil {
				panic(saveErr) // Production code must surface both errors.
			}
			fmt.Println("replacement saved; old revoked:", result.OldRevoked)
			fmt.Println("reconcile old-id without issuing another token")
		}
		return
	}
	// On success, persist result.New.Value before discarding the result.

	// Output:
	// replacement saved; old revoked: false
	// reconcile old-id without issuing another token
}

func ExampleCheckHealth() {
	root, err := os.MkdirTemp("", "credkit-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	ledger := token.NewLedger(filepath.Join(root, "tokens.json"))
	if err := ledger.Record(&token.Metadata{Provider: "example", Name: "deployment", ID: "token-id"}); err != nil {
		panic(err)
	}
	report, err := sts.CheckHealth(context.Background(), exampleProvider{}, ledger, time.Hour)
	if err != nil {
		panic(err)
	}
	total, valid, _, _, _ := report.Counts()
	fmt.Printf("total: %d; validated: %d; unknown: %d\n", total, valid, len(report.Unknown))
	// Output: total: 1; validated: 0; unknown: 1
}
