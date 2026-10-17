package secret

import (
	"strconv"
	"testing"
)

// This target is pure: arbitrary metadata must never invoke the security CLI.
func FuzzKeychainEncodingMetadata(f *testing.F) {
	for _, seed := range []string{"", `"desc"<blob>="credkit.base64.v1"`, "\t\"desc\"<blob>=\"credkit.base64.v1\"\n", `"acct"<blob>="credkit.base64.v1"`, "\x00\xff\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		// Quoting keeps arbitrary item contents inside an unrelated attribute;
		// even embedded marker text must not become encoding evidence.
		unrelated := `"acct"<blob>=` + strconv.Quote(input+encodedKind) + "\n"
		if hasEncodedKind([]byte(unrelated)) {
			t.Fatal("unrelated attribute authorized encoded decoding")
		}
		marker := `"desc"<blob>="credkit.base64.v1"`
		if !hasEncodedKind([]byte(unrelated + " \t" + marker + "\r\n" + unrelated)) {
			t.Fatal("injected exact description marker was not recognized")
		}
		for _, malformed := range []string{
			"prefix" + marker,
			marker + "suffix",
			`"desc"<blob>="credkit.base64.v1-extra"`,
			`"acct"<blob>="credkit.base64.v1"`,
			`"desc"<blob>="` + strconv.Quote(input) + `credkit.base64.v1"`,
		} {
			if hasEncodedKind([]byte(unrelated + malformed + "\n" + unrelated)) {
				t.Fatalf("malformed or embedded marker authorized decoding: %q", malformed)
			}
		}
	})
}
