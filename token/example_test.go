package token_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/albertocavalcante/credkit/token"
)

func ExampleLedger_FindByID() {
	root, err := os.MkdirTemp("", "credkit-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	ledger := token.NewLedger(filepath.Join(root, "tokens.json"))
	for _, entry := range []token.Metadata{
		{Provider: "example", ID: "other-id", Name: "wanted-id"},
		{Provider: "example", ID: "wanted-id", Name: "deployment"},
	} {
		if err := ledger.Record(&entry); err != nil {
			panic(err)
		}
	}
	byID, err := ledger.FindByID("example", "wanted-id")
	if err != nil {
		panic(err)
	}
	byName, err := ledger.FindByName("example", "wanted-id")
	if err != nil {
		panic(err)
	}
	fmt.Println("ID lookup:", byID.Name)
	fmt.Println("name lookup:", byName.ID)
	// Output:
	// ID lookup: deployment
	// name lookup: other-id
}
