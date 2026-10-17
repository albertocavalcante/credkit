package store_test

import (
	"fmt"
	"os"

	"github.com/albertocavalcante/credkit/store"
)

func ExampleWriteSecureAt() {
	root, err := os.MkdirTemp("", "credkit-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)

	// root is trusted by the caller; every managed descendant is checked.
	if err := store.WriteSecureAt(root, "credentials/work", []byte("synthetic")); err != nil {
		panic(err)
	}
	value, err := store.ReadSecureAt(root, "credentials/work")
	if err != nil {
		panic(err)
	}
	fmt.Println("credential loaded:", len(value) > 0)
	// Output: credential loaded: true
}
