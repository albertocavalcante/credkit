package secret

import "context"

// migrateLegacyKeychain is shared with the native legacy-migration oracle.
// The policy must come from knowledge of the old writer, never a guess based
// on the password's b64: prefix. New marked entries need no legacy policy.
func migrateLegacyKeychain(ctx context.Context, key Key, policy LegacyEncoding) error {
	legacy := KeychainStore{LegacyEncoding: policy}
	value, err := legacy.Get(ctx, key)
	if err != nil {
		return err
	}
	return (KeychainStore{}).Put(ctx, key, value)
}

func ExampleKeychainStore_legacyMigration() {
	// This example is compiled; the native migration test executes its helper
	// against temporary Keychain items rather than a user's existing secrets.
	key := Key{Service: "myapp", Account: "work"}
	if err := migrateLegacyKeychain(context.Background(), key, LegacyBase64); err != nil {
		panic(err)
	}
}
