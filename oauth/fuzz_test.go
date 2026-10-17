package oauth_test

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/oauth"
)

func FuzzTokenUnmarshal(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"access_token":"new"}`, `{"access_token":"new","expires_in":1,"custom":true}`, `{"expires_in":9223372036854775807}`, `{"expires_in":-1}`, `{"access_token":4}`, `{"custom":1e1000}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		original := oauth.Token{AccessToken: "old", RefreshToken: "old-refresh", ExpiresAt: time.Unix(123, 0), Extra: map[string]any{"old": true}}
		expected := original
		expected.Extra = map[string]any{"old": true}
		got := original
		before := time.Now()
		err := json.Unmarshal([]byte(input), &got)
		after := time.Now()
		if err != nil {
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("failed decode changed receiver: %#v", got)
			}
			return
		}
		var wire struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal([]byte(input), &wire); err != nil {
			t.Fatalf("successful token has invalid standard fields: %v", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(input), &fields); err != nil {
			t.Fatal(err)
		}
		if _, supplied := fields["old"]; !supplied {
			if _, retained := got.Extra["old"]; retained {
				t.Fatal("successful decode retained an absent old extra field")
			}
		}
		if got.AccessToken != wire.AccessToken {
			t.Fatal("access token did not replace prior value")
		}
		if wire.ExpiresIn <= 0 {
			if !got.ExpiresAt.IsZero() {
				t.Fatal("unknown expiry retained prior expiry")
			}
		} else {
			d := time.Duration(wire.ExpiresIn) * time.Second
			if got.ExpiresAt.Before(before.Add(d)) || got.ExpiresAt.After(after.Add(d)) {
				t.Fatal("expiry outside decode interval")
			}
		}
		for _, key := range []string{"access_token", "refresh_token", "token_type", "scope", "expires_in"} {
			if _, ok := got.Extra[key]; ok {
				t.Fatalf("standard field %q leaked into extras", key)
			}
		}
	})
}

func FuzzAuthCodeURLReservedParameters(f *testing.F) {
	f.Add("state&scope=x", "client", "https://app.example/callback?a=b", "challenge", "openid")
	f.Add("", "", "", "", "")
	f.Add("\x00", "世界", "http://127.0.0.1:1234", "abc+/=", "a b")
	f.Fuzz(func(t *testing.T, state, clientID, redirect, challenge, scope string) {
		if len(state)+len(clientID)+len(redirect)+len(challenge)+len(scope) > 64*1024 {
			t.Skip()
		}
		q := url.Values{"client_id": {"old", "duplicate"}, "state": {"old", "duplicate"}, "scope": {"old"}, "code_challenge": {"old"}, "code_challenge_method": {"plain"}, "extra": {"keep"}}
		c := oauth.Config{AuthURL: "https://auth.example/authorize?" + q.Encode(), ClientID: clientID, RedirectURL: redirect}
		if scope != "" {
			c.Scopes = []string{scope}
		}
		got, err := c.AuthCodeURLChecked(state, oauth.PKCE{Challenge: challenge, Method: oauth.MethodS256})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatal(err)
		}
		values := u.Query()
		for key, want := range map[string]string{"response_type": "code", "client_id": clientID, "redirect_uri": redirect, "state": state, "extra": "keep"} {
			if len(values[key]) != 1 || values.Get(key) != want {
				t.Fatalf("%s = %q, want one %q", key, values[key], want)
			}
		}
		if values.Get("scope") != scope || (scope == "" && values.Has("scope")) {
			t.Fatal("stale or altered scope")
		}
		if challenge == "" {
			if values.Has("code_challenge") || values.Has("code_challenge_method") {
				t.Fatal("stale PKCE parameters")
			}
		} else if len(values["code_challenge"]) != 1 || values.Get("code_challenge") != challenge || values.Get("code_challenge_method") != "S256" {
			t.Fatal("ambiguous PKCE parameters")
		}
	})
}
