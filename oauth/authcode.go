package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	paramCode         = "code"
	paramClientID     = "client_id"
	paramRedirectURI  = "redirect_uri"
	paramRefreshToken = "refresh_token"
)

// MaxTokenResponseBytes bounds decoded token and error responses, after any
// transparent HTTP decompression.
const MaxTokenResponseBytes = 1 << 20

var (
	// ErrTokenRedirect is returned rather than forwarding credentials on redirects.
	ErrTokenRedirect = errors.New("oauth: token endpoint redirects are not allowed")
	// ErrTokenResponseTooLarge identifies token responses over MaxTokenResponseBytes.
	ErrTokenResponseTooLarge = errors.New("oauth: token response exceeds size limit")
	// ErrInvalidTokenResponse identifies a success response without an access token.
	ErrInvalidTokenResponse = errors.New("oauth: token response has no access token")
)

// Config holds the OAuth 2.0 client configuration for a single provider.
// One Config corresponds to one (client, authorization-server) pair.
type Config struct {
	ClientID     string
	ClientSecret string // optional; empty for public clients (the common PKCE case)
	AuthURL      string // authorization endpoint
	TokenURL     string // token endpoint
	RedirectURL  string // must exactly match the one registered with the provider
	Scopes       []string

	// HTTPClient is used for token requests. If nil, a client with a 30 s
	// timeout is used. Token-endpoint redirects are refused using a shallow
	// client copy; the supplied client is never modified.
	HTTPClient *http.Client
}

// AuthCodeURL builds the authorization-endpoint URL for a fresh login.
// The caller should open this URL in a browser and receive the auth code
// at RedirectURL. state must be a cryptographically random value the
// caller verifies on callback to prevent CSRF. Invalid configuration returns
// an empty string; use AuthCodeURLChecked to receive the validation error.
func (c Config) AuthCodeURL(state string, pkce PKCE) string {
	raw, _ := c.AuthCodeURLChecked(state, pkce)
	return raw
}

// Exchange trades an authorization code for an access token.
// verifier is the PKCE code verifier matching the challenge sent to AuthCodeURL.
func (c Config) Exchange(ctx context.Context, code, verifier string) (*Token, error) {
	form := url.Values{
		"grant_type":     {"authorization_code"},
		paramCode:        {code},
		paramRedirectURI: {c.RedirectURL},
		paramClientID:    {c.ClientID},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	return c.postTokenForm(ctx, form)
}

// Refresh uses a refresh token to obtain a new access token. Some providers
// rotate the refresh token; if the response includes a new refresh_token,
// callers must store it and discard the old one.
func (c Config) Refresh(ctx context.Context, refreshToken string) (*Token, error) {
	form := url.Values{
		"grant_type":      {"refresh_token"},
		paramRefreshToken: {refreshToken},
		paramClientID:     {c.ClientID},
	}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	return c.postTokenForm(ctx, form)
}

func (c Config) postTokenForm(ctx context.Context, form url.Values) (*Token, error) {
	if c.TokenURL == "" {
		return nil, errors.New("oauth: Config.TokenURL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrTokenRedirect }
	resp, err := requestClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: post token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("oauth: read token response: %w", err)
	}

	if len(body) > MaxTokenResponseBytes {
		return nil, ErrTokenResponseTooLarge
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseTokenError(resp.StatusCode, body)
	}

	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oauth: parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		te := parseTokenError(resp.StatusCode, body)
		if te.Code != "" {
			return nil, te
		}
		return nil, ErrInvalidTokenResponse
	}
	return &tok, nil
}

func parseTokenError(status int, body []byte) *TokenError {
	te := &TokenError{HTTPStatus: status, Body: append([]byte(nil), body...)}
	var wire struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	if err := json.Unmarshal(body, &wire); err == nil {
		te.Code = wire.Error
		te.Description = wire.ErrorDescription
		te.URI = wire.ErrorURI
	}
	return te
}

// AuthCodeURLChecked builds an authorization URL with explicit validation errors.
func (c Config) AuthCodeURLChecked(state string, pkce PKCE) (string, error) {
	u, err := url.Parse(c.AuthURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Fragment != "" {
		return "", errors.New("oauth: invalid authorization endpoint")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("oauth: invalid authorization endpoint query")
	}
	q.Set("response_type", "code")
	q.Set(paramClientID, c.ClientID)
	q.Set(paramRedirectURI, c.RedirectURL)
	q.Set("state", state)
	q.Del("scope")
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	if len(c.Scopes) > 0 {
		q.Set("scope", strings.Join(c.Scopes, " "))
	}
	if pkce.Challenge != "" {
		if pkce.Method != MethodS256 {
			return "", errors.New("oauth: authorization requires S256 PKCE")
		}
		q.Set("code_challenge", pkce.Challenge)
		q.Set("code_challenge_method", string(pkce.Method))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
