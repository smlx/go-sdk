// Copyright 2026 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

// In a real application, you might write these to a keyring or state storage.
func save(config *oauth2.Config, token *oauth2.Token) error {
	return nil
}

// In a real application, you might load these from a keyring or state storage.
func restore() (*oauth2.Config, *oauth2.Token, error) {
	return nil, nil, nil
}

// savingTokenSource is an oauth2.TokenSource that saves the config and
// token to the given saver function each time the token is refreshed.
type savingTokenSource struct {
	mu          sync.Mutex
	src         oauth2.TokenSource
	saver       func(*oauth2.Config, *oauth2.Token) error
	config      *oauth2.Config
	accessToken string
}

func (s *savingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := s.src.Token()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	changed := s.accessToken != tok.AccessToken
	if changed {
		s.accessToken = tok.AccessToken
	}
	s.mu.Unlock()
	if changed {
		_ = s.saver(s.config, tok)
	}
	return tok, nil
}

// NewSavingTokenSource persists OAuth 2.0 sessions by intercepting token
// refreshes from the wrapped oauth2.TokenSource. When this wrapper detects
// an access token refresh, it calls the provided session saver with the
// oauth2.Config and the new oauth2.Token.
func NewSavingTokenSource(wrapped oauth2.TokenSource, config *oauth2.Config, initialToken *oauth2.Token, saver func(*oauth2.Config, *oauth2.Token) error) oauth2.TokenSource {
	if wrapped == nil {
		return nil
	}
	if saver == nil {
		return wrapped
	}
	var accessToken string
	if initialToken != nil {
		accessToken = initialToken.AccessToken
	}
	return &savingTokenSource{
		src:         wrapped,
		saver:       saver,
		config:      config,
		accessToken: accessToken,
	}
}

// persistentOAuthHandler implements auth.OAuthHandler and demonstrates how to
// integrate oauth2 session persistence.
type persistentOAuthHandler struct {
	mu          sync.Mutex
	tokenSource oauth2.TokenSource
}

// TokenSource returns a token source used by the transport.
func (h *persistentOAuthHandler) TokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Use existing token source if already initialized.
	if h.tokenSource != nil {
		return h.tokenSource, nil
	}

	// Try to restore a previously saved session.
	cfg, tok, err := restore()
	if err != nil || cfg == nil || tok == nil {
		// If no session is found, return nil to let the transport call Authorize.
		return nil, nil
	}

	// Wrap the base TokenSource to intercept and persist any token refreshes.
	h.tokenSource = NewSavingTokenSource(cfg.TokenSource(ctx, tok), cfg, tok, save)
	return h.tokenSource, nil
}

// Authorize performs the OAuth flow and sets up the token source.
func (h *persistentOAuthHandler) Authorize(ctx context.Context, req *http.Request, resp *http.Response) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// In a real implementation, you would perform an OAuth flow here
	// (e.g., using auth.NewAuthorizationCodeHandler) to obtain a new
	// *oauth2.Config and *oauth2.Token.
	mockConfig := &oauth2.Config{ClientID: "example"}
	mockToken := &oauth2.Token{AccessToken: "new-token"}

	// Save the initial session immediately upon successful authorization.
	_ = save(mockConfig, mockToken)

	// Set up the persistent token source for future requests.
	h.tokenSource = NewSavingTokenSource(mockConfig.TokenSource(ctx, mockToken), mockConfig, mockToken, save)

	return nil
}

// This example shows how oauth2 session persistence might be implemented.
func Example_persistence() {
	handler := &persistentOAuthHandler{}

	// Implement a persistent OAuthHandler that can be set on a transport
	// supports OAuth. The transport will call TokenSource(), and if no session
	// exists, it will call Authorize() which persists the newly acquired
	// session.
	_ = auth.OAuthHandler(handler)

	fmt.Println("Configured persistent OAuth handler.")
	// Output:
	// Configured persistent OAuth handler.
}
