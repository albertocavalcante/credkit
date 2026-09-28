package oauth

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CallbackOptions configures the local HTTP server that receives the
// authorization-server redirect during the auth-code flow.
type CallbackOptions struct {
	// Port to listen on. Zero means pick a free port (recommended for CLIs).
	Port int

	// Path the authorization server will redirect to (e.g. "/callback").
	// Must match the path component of the RedirectURL registered with the
	// provider. Defaults to "/callback".
	Path string

	// SuccessHTML is the HTML body returned to the browser after a successful
	// redirect. Empty uses a minimal default.
	SuccessHTML string

	// ErrorHTML is the HTML body returned on an error redirect. Empty uses a
	// minimal default.
	ErrorHTML string
}

// CallbackResult is delivered when the authorization server redirects to the
// local server with a successful response.
type CallbackResult struct {
	Code  string
	State string
}

// CallbackServer is a single-shot HTTP server that captures one OAuth 2.0
// authorization-code redirect. Wait blocks until a redirect arrives or ctx
// is canceled. The server stops accepting new requests after the first
// non-favicon callback is processed.
type CallbackServer struct {
	srv      *http.Server
	listener net.Listener
	path     string

	once   sync.Once
	result chan callbackEvent
}

type callbackEvent struct {
	res CallbackResult
	err error
}

// StartCallbackServer binds a local listener and starts serving the redirect
// handler in the background. The caller must Close the server when done.
func StartCallbackServer(opts CallbackOptions) (*CallbackServer, error) {
	if opts.Path == "" {
		opts.Path = "/callback"
	}
	if !strings.HasPrefix(opts.Path, "/") {
		opts.Path = "/" + opts.Path
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", opts.Port))
	if err != nil {
		return nil, fmt.Errorf("oauth: bind callback listener: %w", err)
	}

	cb := &CallbackServer{
		listener: ln,
		path:     opts.Path,
		result:   make(chan callbackEvent, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(opts.Path, cb.handler(opts))

	cb.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = cb.srv.Serve(ln) }()
	return cb, nil
}

// RedirectURL returns the URL the caller should register with the provider
// and pass as Config.RedirectURL.
func (cb *CallbackServer) RedirectURL() string {
	return "http://" + cb.listener.Addr().String() + cb.path
}

// Wait blocks until the authorization server redirects or ctx is done.
// On error redirects (e.g. user denied consent), the returned error is a
// *TokenError carrying the error code from the redirect.
//
// The caller is responsible for verifying CallbackResult.State against
// the state passed to Config.AuthCodeURL. Use VerifyState for a
// constant-time comparison. Skipping this check exposes the flow to CSRF
// per RFC 6749 §10.12.
func (cb *CallbackServer) Wait(ctx context.Context) (CallbackResult, error) {
	select {
	case ev := <-cb.result:
		return ev.res, ev.err
	case <-ctx.Done():
		return CallbackResult{}, ctx.Err()
	}
}

// Close shuts down the server. Safe to call multiple times.
func (cb *CallbackServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return cb.srv.Shutdown(ctx)
}

func (cb *CallbackServer) handler(opts CallbackOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Error redirect (RFC 6749 §4.1.2.1).
		if errCode := q.Get("error"); errCode != "" {
			err := &TokenError{
				Code:        errCode,
				Description: q.Get("error_description"),
				URI:         q.Get("error_uri"),
			}
			cb.deliver(callbackEvent{err: err})
			writeBody(w, http.StatusBadRequest, opts.ErrorHTML, defaultErrorHTML(errCode))
			return
		}

		code := q.Get(paramCode)
		if code == "" {
			cb.deliver(callbackEvent{err: errors.New("oauth: callback missing 'code' parameter")})
			writeBody(w, http.StatusBadRequest, opts.ErrorHTML, defaultErrorHTML("missing code"))
			return
		}

		cb.deliver(callbackEvent{res: CallbackResult{Code: code, State: q.Get("state")}})
		writeBody(w, http.StatusOK, opts.SuccessHTML, defaultSuccessHTML)
	}
}

// deliver sends the first event and ignores subsequent ones, so a stray
// favicon request after the real callback can't overwrite the result.
func (cb *CallbackServer) deliver(ev callbackEvent) {
	cb.once.Do(func() { cb.result <- ev })
}

func writeBody(w http.ResponseWriter, status int, custom, fallback string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	body := custom
	if body == "" {
		body = fallback
	}
	// Default query-derived error text is escaped by defaultErrorHTML. Custom
	// HTML is trusted markup supplied by the application through CallbackOptions.
	_, _ = w.Write([]byte(body)) // #nosec G705 -- trusted custom HTML; dynamic default error text is escaped.
}

const defaultSuccessHTML = `<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
<h2>Login complete</h2><p>You can close this window and return to your terminal.</p></body></html>`

func defaultErrorHTML(reason string) string {
	return `<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
<h2>Login failed</h2><p>` + html.EscapeString(reason) + `</p></body></html>`
}
