package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthCodeURLBuilds(t *testing.T) {
	cfg := Config{
		ClientID:    "client-abc",
		AuthURL:     "https://issuer.example/authorize",
		TokenURL:    "https://issuer.example/token",
		RedirectURL: "http://localhost:8765/callback",
		Scopes:      []string{"read", "write"},
	}
	pkce := PKCE{Verifier: "v", Challenge: "ch", Method: MethodS256}

	raw := cfg.AuthCodeURL("state-xyz", pkce)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://issuer.example/authorize" {
		t.Errorf("unexpected endpoint: %s", raw)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "client-abc",
		"redirect_uri":          "http://localhost:8765/callback",
		"scope":                 "read write",
		"state":                 "state-xyz",
		"code_challenge":        "ch",
		"code_challenge_method": "S256",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
}

func TestAuthCodeURLNoScopes(t *testing.T) {
	cfg := Config{
		ClientID:    "c",
		AuthURL:     "https://i/authorize",
		RedirectURL: "https://app/cb",
	}
	pkce := PKCE{Challenge: "ch", Method: MethodS256}
	raw := cfg.AuthCodeURL("s", pkce)
	u, _ := url.Parse(raw)
	if _, present := u.Query()["scope"]; present {
		t.Error("scope should be omitted when Scopes is empty")
	}
}

func TestExchangeSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("server ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("code"); got != "auth-code-1" {
			t.Errorf("code = %q", got)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-v1" {
			t.Errorf("code_verifier = %q", got)
		}
		if got := r.Form.Get("client_id"); got != "cid" {
			t.Errorf("client_id = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"access_token":"at-1",
			"refresh_token":"rt-1",
			"token_type":"Bearer",
			"expires_in":3600,
			"scope":"read write"
		}`)
	}))
	defer srv.Close()

	cfg := Config{
		ClientID:    "cid",
		AuthURL:     "https://unused",
		TokenURL:    srv.URL,
		RedirectURL: "https://unused/cb",
	}
	before := time.Now()
	tok, err := cfg.Exchange(context.Background(), "auth-code-1", "verifier-v1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "at-1" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-1" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", tok.TokenType)
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set when expires_in is present")
	}
	if delta := tok.ExpiresAt.Sub(before); delta < 50*time.Minute || delta > 70*time.Minute {
		t.Errorf("ExpiresAt offset %v not near 1h", delta)
	}
	if tok.Scope != "read write" {
		t.Errorf("Scope = %q", tok.Scope)
	}
}

func TestExchangeErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"code expired"}`)
	}))
	defer srv.Close()

	cfg := Config{ClientID: "c", TokenURL: srv.URL, RedirectURL: "https://app/cb"}
	_, err := cfg.Exchange(context.Background(), "bad", "v")
	if err == nil {
		t.Fatal("expected error")
	}
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TokenError, got %T: %v", err, err)
	}
	if te.Code != "invalid_grant" {
		t.Errorf("Code = %q, want invalid_grant", te.Code)
	}
	if !strings.Contains(te.Error(), "code expired") {
		t.Errorf("error message should include description: %q", te.Error())
	}
}

func TestExchangeNonJSONErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "upstream exploded")
	}))
	defer srv.Close()

	cfg := Config{ClientID: "c", TokenURL: srv.URL, RedirectURL: "https://app/cb"}
	_, err := cfg.Exchange(context.Background(), "code", "v")
	if err == nil {
		t.Fatal("expected error")
	}
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TokenError, got %T", err)
	}
	if te.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("HTTPStatus = %d", te.HTTPStatus)
	}
}

func TestRefreshSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("refresh_token"); got != "old-rt" {
			t.Errorf("refresh_token = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"new-at","token_type":"Bearer","expires_in":1800}`)
	}))
	defer srv.Close()

	cfg := Config{ClientID: "c", TokenURL: srv.URL, RedirectURL: "https://app/cb"}
	tok, err := cfg.Refresh(context.Background(), "old-rt")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "new-at" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
}

func TestTokenExpired(t *testing.T) {
	if (&Token{}).Expired() {
		t.Error("zero ExpiresAt should be treated as 'no known expiry' (not expired)")
	}
	if (&Token{ExpiresAt: time.Now().Add(time.Hour)}).Expired() {
		t.Error("future ExpiresAt should not be expired")
	}
	if !(&Token{ExpiresAt: time.Now().Add(-time.Minute)}).Expired() {
		t.Error("past ExpiresAt should be expired")
	}
}

func TestParseTokenJSONExtraFields(t *testing.T) {
	// Provider-specific fields should be preserved in Extra for provider adapters.
	data := []byte(`{"access_token":"at","token_type":"Bearer","id_token":"jwt.here","custom_field":42}`)
	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tok.Extra["id_token"] != "jwt.here" {
		t.Errorf("expected id_token in Extra, got %v", tok.Extra)
	}
	// json numbers decode as float64.
	if v, ok := tok.Extra["custom_field"].(float64); !ok || v != 42 {
		t.Errorf("expected custom_field=42 in Extra, got %v", tok.Extra["custom_field"])
	}
}
