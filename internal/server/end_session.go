package server

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	zhttp "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Static errors for end session
var (
	ErrRedirectURIMustBeAbsolute = errors.New("redirect URI must be absolute")
	ErrRedirectURIMustUseHTTPS   = errors.New("redirect URI must use http or https scheme")
)

const (
	postLogoutRedirectCookieName  = "oidcld_post_logout_redirect_uri"
	logoutSuccessRedirectDelaySec = 3
)

// Decoder implements SessionEnder for the OIDC server.
func (s *Server) Decoder() zhttp.Decoder {
	// Return a simple decoder - we can implement this interface ourselves
	return &SimpleDecoder{}
}

// SimpleDecoder implements a basic decoder for form data
type SimpleDecoder struct{}

func (d *SimpleDecoder) Decode(_ any, src map[string][]string) error {
	// For now, return nil - the zitadel/oidc library will handle the actual parsing
	// This is just to satisfy the interface requirement
	_ = src // Acknowledge we're not using src either
	return nil
}

func (s *Server) Storage() op.Storage {
	return s.storage
}

func (s *Server) IDTokenHintVerifier(ctx context.Context) *op.IDTokenHintVerifier {
	// For now, return nil to disable ID token hint verification
	// In a full implementation, we would create a proper KeySet from the storage keys
	return nil
}

func (s *Server) DefaultLogoutRedirectURI() string {
	// Return default logout success page URL
	return s.config.OIDC.Issuer + "/logout/success"
}

func (s *Server) Logger() *slog.Logger {
	return s.logger
}

// UserSession represents a user session for tracking and termination
type UserSession struct {
	UserID        string
	ClientID      string
	SessionID     string
	CreatedAt     time.Time
	LastActivity  time.Time
	AccessTokens  []string
	RefreshTokens []string
}

// Session and token management methods for the storage adapter
func (s *StorageAdapter) createUserSession(userID, clientID string) *UserSession {
	s.lock.Lock()
	defer s.lock.Unlock()

	sessionID := fmt.Sprintf("%s:%s", userID, clientID)
	session := &UserSession{
		UserID:        userID,
		ClientID:      clientID,
		SessionID:     sessionID,
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		AccessTokens:  make([]string, 0),
		RefreshTokens: make([]string, 0),
	}

	// Store session (we'll add a sessions map to the storage adapter)
	if s.userSessions == nil {
		s.userSessions = make(map[string]*UserSession)
	}
	s.userSessions[sessionID] = session

	return session
}

func (s *StorageAdapter) terminateUserSession(userID, clientID string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.terminateUserSessionLocked(userID, clientID)
}

func (s *StorageAdapter) terminateUserSessionLocked(userID, clientID string) {
	// Find and terminate user sessions
	for sessionID, session := range s.userSessions {
		if session.UserID == userID && (clientID == "" || session.ClientID == clientID) {
			// Invalidate all tokens for this session
			s.invalidateSessionTokens(session)

			// Remove session
			delete(s.userSessions, sessionID)
		}
	}
}

func (s *StorageAdapter) invalidateSessionTokens(session *UserSession) {
	// Invalidate access tokens
	for _, tokenID := range session.AccessTokens {
		delete(s.tokens, tokenID)
		if s.tokenIndex != nil {
			delete(s.tokenIndex, tokenID)
		}
	}

	// Invalidate refresh tokens
	for _, tokenID := range session.RefreshTokens {
		delete(s.refreshTokens, tokenID)
	}
}

func (s *StorageAdapter) trackTokenForSession(userID, clientID, tokenID, tokenType string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	sessionKey := fmt.Sprintf("%s:%s", userID, clientID)
	session, exists := s.userSessions[sessionKey]
	if !exists {
		session = &UserSession{
			UserID:        userID,
			ClientID:      clientID,
			SessionID:     sessionKey,
			CreatedAt:     time.Now(),
			AccessTokens:  make([]string, 0),
			RefreshTokens: make([]string, 0),
		}
		if s.userSessions == nil {
			s.userSessions = make(map[string]*UserSession)
		}
		s.userSessions[sessionKey] = session
	}

	// Track token in session
	switch tokenType {
	case "access_token":
		session.AccessTokens = append(session.AccessTokens, tokenID)
	case "refresh_token":
		session.RefreshTokens = append(session.RefreshTokens, tokenID)
	}

	// Update token index
	if s.tokenIndex == nil {
		s.tokenIndex = make(map[string]string)
	}
	s.tokenIndex[tokenID] = userID
	session.LastActivity = time.Now()
}

// TerminateSessionFromRequest implements CanTerminateSessionFromRequest for enhanced session termination.
func (s *StorageAdapter) TerminateSessionFromRequest(_ context.Context, endSessionRequest *op.EndSessionRequest) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Terminate user session and invalidate tokens
	if endSessionRequest.UserID != "" {
		s.terminateUserSessionLocked(endSessionRequest.UserID, endSessionRequest.ClientID)
	}

	// Return redirect URI (empty for default behavior)
	return endSessionRequest.RedirectURI, nil
}

// Custom logout success page handler
func (s *Server) handleLogoutSuccess(w http.ResponseWriter, r *http.Request) {
	s.showLogoutSuccessPage(w, r)
}

// showLogoutSuccessPage displays an enhanced logout success page
func (s *Server) showLogoutSuccessPage(w http.ResponseWriter, r *http.Request) {
	redirectTarget := s.postLogoutRedirectURIFromRequest(r)
	if redirectTarget != "" {
		s.clearPostLogoutRedirectCookie(w, r)
	}

	metaRefresh := ""
	redirectMessage := "<p>You can now close this window or navigate to your application.</p>"
	if redirectTarget != "" {
		escapedTarget := html.EscapeString(redirectTarget)
		metaRefresh = fmt.Sprintf("\n    <meta http-equiv=\"refresh\" content=\"%d;url=%s\">", logoutSuccessRedirectDelaySec, escapedTarget)
		redirectMessage = fmt.Sprintf(`<p>You will be redirected back to your application in a few seconds. If nothing happens, <a href="%s">return now</a>.</p>`, escapedTarget)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logout Successful - OpenID Connect Test IdP</title>__META_REFRESH__
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }

        .success {
            color: #28a745;
        }

        p {
            line-height: 1.6;
        }

        a {
            color: #0d6efd;
        }
    </style>
</head>
<body>
    <h1 class="success">✓ Successfully Logged Out</h1>
    <p>You have been successfully logged out from the OIDC Test Identity Provider.</p>
    __REDIRECT_MESSAGE__
</body>
</html>`

	html = strings.ReplaceAll(html, "__META_REFRESH__", metaRefresh)
	html = strings.ReplaceAll(html, "__REDIRECT_MESSAGE__", redirectMessage)

	w.Write([]byte(html))
	if redirectTarget != "" {
		s.logger.Info("Logout success page displayed", "post_logout_redirect_uri", redirectTarget)
		return
	}
	s.logger.Info("Logout success page displayed")
}

func (s *Server) postLogoutRedirectURIFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	if redirectURI := r.URL.Query().Get("post_logout_redirect_uri"); redirectURI != "" {
		return redirectURI
	}

	cookie, err := r.Cookie(postLogoutRedirectCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}

	redirectURI, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return ""
	}
	return redirectURI
}

func (s *Server) rememberPostLogoutRedirectCookie(w http.ResponseWriter, r *http.Request) {
	if w == nil || r == nil {
		return
	}

	redirectURI := requestParameter(r, "post_logout_redirect_uri")
	if redirectURI == "" {
		return
	}
	if err := s.validatePostLogoutRedirectURI(redirectURI); err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     postLogoutRedirectCookieName,
		Value:    url.QueryEscape(redirectURI),
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func (s *Server) clearPostLogoutRedirectCookie(w http.ResponseWriter, r *http.Request) {
	if w == nil || r == nil {
		return
	}

	if _, err := r.Cookie(postLogoutRedirectCookieName); err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     postLogoutRedirectCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

// validatePostLogoutRedirectURI validates the post logout redirect URI
func (s *Server) validatePostLogoutRedirectURI(redirectURI string) error {
	if redirectURI == "" {
		return nil // Optional parameter
	}

	// Parse URI
	parsedURI, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect URI format: %w", err)
	}

	// Must be absolute URI
	if !parsedURI.IsAbs() {
		return ErrRedirectURIMustBeAbsolute
	}

	// Security: only allow http/https
	if parsedURI.Scheme != "http" && parsedURI.Scheme != "https" {
		return ErrRedirectURIMustUseHTTPS
	}

	// In production, validate against client's registered post-logout redirect URIs
	// For test IdP, we'll be permissive but secure
	return nil
}
