package oauth_test

import (
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/albertocavalcante/credkit/oauth"
)

func TestCallbackEscapesErrorReason(t *testing.T) {
	for _, reason := range []string{`<script>alert(1)</script>`, `<img src=x onerror="alert(1)">`, `denied & unavailable`} {
		t.Run(reason, func(t *testing.T) {
			server, err := oauth.StartCallbackServer(oauth.CallbackOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			response, err := http.Get(server.RedirectURL() + "?error=" + url.QueryEscape(reason))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), html.EscapeString(reason)) {
				t.Fatalf("status=%d body=%s; want escaped error", response.StatusCode, body)
			}
			_, err = server.Wait(t.Context())
			var tokenError *oauth.TokenError
			if !errors.As(err, &tokenError) || tokenError.Code != reason {
				t.Fatalf("callback structured error changed: %v", err)
			}
		})
	}
}

func TestCallbackSupportsApplicationSuppliedHTML(t *testing.T) {
	custom := `<main><strong>Application error page</strong></main>`
	server, err := oauth.StartCallbackServer(oauth.CallbackOptions{ErrorHTML: custom})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response, err := http.Get(server.RedirectURL() + "?error=" + url.QueryEscape(`<script>alert(1)</script>`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != custom || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("custom HTML changed: status=%d body=%q", response.StatusCode, body)
	}
}
