package oauth_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/albertocavalcante/credkit/oauth"
)

func TestErrorCallbackPreservesState(t *testing.T) {
	cb, err := oauth.StartCallbackServer(oauth.CallbackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	resp, err := http.Get(cb.RedirectURL() + "?error=access_denied&state=expected-state")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	res, err := cb.Wait(t.Context())
	if err == nil {
		t.Fatal("expected denial")
	}
	if res.State != "expected-state" {
		t.Fatalf("error redirect discarded state; result=%+v err=%v", res, err)
	}
}

func TestInvalidCallbackPathDoesNotPanicOrLeakListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	address := ln.Addr().String()
	ln.Close()
	defer func() {
		if p := recover(); p != nil {
			rebound, bindErr := net.Listen("tcp", address)
			if rebound != nil {
				rebound.Close()
			}
			t.Fatalf("invalid callback path panics: %v; rebinding its address fails: %v", p, bindErr)
		}
	}()
	cb, err := oauth.StartCallbackServer(oauth.CallbackOptions{Port: port, Path: "/callback/{invalid"})
	if cb != nil {
		defer cb.Close()
	}
	if err == nil {
		t.Fatal("invalid path accepted")
	}
	rebound, bindErr := net.Listen("tcp", address)
	if bindErr != nil {
		t.Fatalf("failed construction leaked listener: %v", bindErr)
	}
	rebound.Close()
}

func TestAuthorizationURLDoesNotDuplicateReservedParams(t *testing.T) {
	raw := (oauth.Config{ClientID: "new-client", AuthURL: "https://example.invalid/auth?client_id=old-client&audience=api", RedirectURL: "http://127.0.0.1/callback"}).AuthCodeURL("state", oauth.PKCE{})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query()["client_id"]; len(got) != 1 || got[0] != "new-client" {
		t.Fatalf("conflicting reserved parameters: %v", got)
	}
}

func TestExpectedStateRejectsUnrelatedCallbacks(t *testing.T) {
	cb, err := oauth.StartCallbackServer(oauth.CallbackOptions{ExpectedState: "expected"})
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	resp, err := http.Get(cb.RedirectURL() + "?error=access_denied&state=wrong")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if _, err := cb.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unrelated callback consumed result: %v", err)
	}
	resp, err = http.Get(cb.RedirectURL() + "?code=real&state=expected")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got, err := cb.Wait(t.Context())
	if err != nil || got.Code != "real" {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestCheckedAuthorizationURLRejectsInvalidEndpoints(t *testing.T) {
	for _, endpoint := range []string{"https://issuer.invalid/auth#fragment", "://bad", "ftp://issuer.invalid/auth"} {
		cfg := oauth.Config{AuthURL: endpoint}
		if _, err := cfg.AuthCodeURLChecked("state", oauth.PKCE{}); err == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
}

func TestAuthorizationURLKeepsOnlyConfiguredReservedValues(t *testing.T) {
	cfg := oauth.Config{ClientID: "new", RedirectURL: "http://localhost/callback", AuthURL: "https://issuer.invalid/auth?audience=api&state=old&scope=old&code_challenge=old&code_challenge_method=plain"}
	raw, err := cfg.AuthCodeURLChecked("new-state", oauth.PKCE{})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("audience") != "api" || q.Get("state") != "new-state" || q.Has("scope") || q.Has("code_challenge") || q.Has("code_challenge_method") {
		t.Fatalf("query=%v", q)
	}
}
