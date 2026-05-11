package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCallbackServerHappyPath(t *testing.T) {
	srv, err := StartCallbackServer(CallbackOptions{Path: "/callback"})
	if err != nil {
		t.Fatalf("StartCallbackServer: %v", err)
	}
	defer srv.Close()

	redirect := srv.RedirectURL()
	if !strings.HasPrefix(redirect, "http://127.0.0.1:") {
		t.Errorf("unexpected RedirectURL: %s", redirect)
	}
	if !strings.HasSuffix(redirect, "/callback") {
		t.Errorf("RedirectURL missing path: %s", redirect)
	}

	// Simulate the browser redirect from the authorization server.
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = http.Get(redirect + "?code=auth-1&state=s-1")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := srv.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.Code != "auth-1" {
		t.Errorf("Code = %q", result.Code)
	}
	if result.State != "s-1" {
		t.Errorf("State = %q", result.State)
	}
}

func TestCallbackServerErrorRedirect(t *testing.T) {
	srv, err := StartCallbackServer(CallbackOptions{Path: "/cb"})
	if err != nil {
		t.Fatalf("StartCallbackServer: %v", err)
	}
	defer srv.Close()

	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = http.Get(srv.RedirectURL() + "?error=access_denied&error_description=user+declined")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = srv.Wait(ctx)
	if err == nil {
		t.Fatal("expected error from access_denied redirect")
	}
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TokenError, got %T: %v", err, err)
	}
	if te.Code != "access_denied" {
		t.Errorf("Code = %q", te.Code)
	}
}

func TestCallbackServerContextCancel(t *testing.T) {
	srv, err := StartCallbackServer(CallbackOptions{Path: "/cb"})
	if err != nil {
		t.Fatalf("StartCallbackServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = srv.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}
