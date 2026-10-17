package oauth_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/albertocavalcante/credkit/oauth"
)

func TestTokenDecodeReplacesDerivedFields(t *testing.T) {
	var tok oauth.Token
	if err := json.Unmarshal([]byte(`{"access_token":"old","expires_in":10,"id_token":"old-id"}`), &tok); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"access_token":"new"}`), &tok); err != nil {
		t.Fatal(err)
	}
	if !tok.ExpiresAt.IsZero() || len(tok.Extra) > 0 {
		t.Fatalf("replacement token retained old expiry or claims: expiry=%v extras=%v", tok.ExpiresAt, tok.Extra)
	}
}

func TestTokenExpiryDoesNotOverflow(t *testing.T) {
	var tok oauth.Token
	if err := json.Unmarshal([]byte(`{"access_token":"new","expires_in":9223372037}`), &tok); err != nil {
		return
	}
	if tok.Expired() {
		t.Fatalf("positive ~292 year expires_in wraps into expired token: %v", tok.ExpiresAt)
	}
}

func TestTokenRequestRejectsMissingAccessToken(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"error":"invalid_grant"}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }))
			defer srv.Close()
			tok, err := (oauth.Config{TokenURL: srv.URL}).Exchange(t.Context(), "code", "")
			if err == nil {
				t.Fatalf("malformed successful token response accepted: token=%+v", tok)
			}
		})
	}
}

func TestTokenRedirectDoesNotForwardCredentials(t *testing.T) {
	for _, mode := range []string{"different-host", "https-to-http"} {
		t.Run(mode, func(t *testing.T) {
			var stolen string
			dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				stolen = string(body)
				io.WriteString(w, `{"access_token":"x"}`)
			}))
			defer dst.Close()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, strings.Replace(dst.URL, "127.0.0.1", "localhost", 1), http.StatusTemporaryRedirect)
			})
			var src *httptest.Server
			if mode == "https-to-http" {
				src = httptest.NewTLSServer(handler)
			} else {
				src = httptest.NewServer(handler)
			}
			defer src.Close()
			config := oauth.Config{TokenURL: src.URL, ClientID: "id", ClientSecret: "synthetic-client-secret"}
			if mode == "https-to-http" {
				config.HTTPClient = src.Client()
			}
			_, err := config.Refresh(t.Context(), "synthetic-refresh-token")
			if strings.Contains(stolen, "synthetic-refresh-token") || strings.Contains(stolen, "synthetic-client-secret") {
				t.Fatalf("cross-origin redirect received entire credential form: %s (err=%v)", stolen, err)
			}
		})
	}
}

func TestTokenResponseIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, strings.Repeat(" ", 2<<20)+`{"access_token":"x"}`)
	}))
	defer srv.Close()
	_, err := (oauth.Config{TokenURL: srv.URL}).Exchange(t.Context(), "code", "")
	if err == nil {
		t.Fatal("accepted a token response above the supported limit")
	}
}

func TestTokenDecodeErrorPreservesPreviousValue(t *testing.T) {
	tok := oauth.Token{AccessToken: "old"}
	err := json.Unmarshal([]byte(`{"access_token":"new","expires_in":9223372037}`), &tok)
	if err == nil || tok.AccessToken != "old" {
		t.Fatalf("got token=%+v err=%v", tok, err)
	}
}

func TestTokenResponseSizeBoundaries(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(map[int]string{0: "exact", 1: "over"}[extra], func(t *testing.T) {
			tokenJSON := `{"access_token":"x"}`
			body := strings.Repeat(" ", oauth.MaxTokenResponseBytes-len(tokenJSON)+extra) + tokenJSON
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }))
			defer srv.Close()
			_, err := (oauth.Config{TokenURL: srv.URL}).Exchange(t.Context(), "code", "")
			if extra == 0 && err != nil {
				t.Fatal(err)
			}
			if extra == 1 && !errors.Is(err, oauth.ErrTokenResponseTooLarge) {
				t.Fatalf("got %v, want size error", err)
			}
		})
	}
}

func TestTokenRedirectPolicyDoesNotMutateClient(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/destination", status) }))
			defer srv.Close()
			client := srv.Client()
			_, err := (oauth.Config{TokenURL: srv.URL, HTTPClient: client}).Refresh(t.Context(), "synthetic")
			if !errors.Is(err, oauth.ErrTokenRedirect) {
				t.Fatalf("got %v, want redirect error", err)
			}
			if client.CheckRedirect != nil {
				t.Fatal("supplied client was modified")
			}
		})
	}
}
