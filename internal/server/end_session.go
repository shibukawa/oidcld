package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	zhttp "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Static errors for end session
var (
	ErrRedirectURIMustBeAbsolute = errors.New("redirect URI must be absolute")
	ErrRedirectURIMustUseHTTPS   = errors.New("redirect URI must use http or https scheme")
)

// Implement SessionEnder interface for the OIDC server
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
	return s.config.OIDCLD.Issuer + "/logout/success"
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
func (s *Server) showLogoutSuccessPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logout Successful - OpenID Connect Test IdP</title>
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --success-color: #48bb78;
            --text-color: #333;
            --text-muted: #666;
            --background: #f8f9fa;
            --card-background: #ffffff;
            --border-radius: 12px;
            --shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        @media (prefers-color-scheme: dark) {
            :root {
                --text-color: #ffffff;
                --text-muted: #cccccc;
                --background: #1a1a1a;
                --card-background: #2d2d2d;
            }
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: var(--card-background);
            padding: 3rem 2rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            text-align: center;
            max-width: 500px;
            width: 100%;
            animation: slideUp 0.5s ease-out;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .success-icon {
            font-size: 5rem;
            color: var(--success-color);
            margin-bottom: 1.5rem;
            animation: checkmark 0.6s ease-in-out 0.3s both;
        }
        
        @keyframes checkmark {
            0% { transform: scale(0); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }
        
        h1 {
            color: var(--text-color);
            margin-bottom: 1rem;
            font-size: 2rem;
            font-weight: 600;
        }
        
        .subtitle {
            color: var(--text-muted);
            margin-bottom: 2rem;
            font-size: 1.1rem;
            line-height: 1.5;
        }
        
        .info-cards {
            display: grid;
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .info-card {
            background: var(--background);
            padding: 1.5rem;
            border-radius: 8px;
            border-left: 4px solid var(--primary-color);
            text-align: left;
        }
        
        .info-card h3 {
            color: var(--primary-color);
            font-size: 1rem;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        
        .info-card p {
            color: var(--text-muted);
            font-size: 0.9rem;
            line-height: 1.4;
            margin: 0;
        }
        
        .security-notice {
            background: #e8f5e8;
            border-left-color: var(--success-color);
        }
        
        .next-steps {
            background: #e3f2fd;
            border-left-color: #2196f3;
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 2rem 1.5rem;
            }
            
            h1 {
                font-size: 1.5rem;
            }
            
            .success-icon {
                font-size: 4rem;
            }
        }
        
        /* Accessibility */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✅</div>
        <h1>Logout Successful</h1>
        <p class="subtitle">You have been successfully logged out from the OpenID Connect Test Identity Provider.</p>
        
        <div class="info-cards">
            <div class="info-card security-notice">
                <h3>🔒 Security Notice</h3>
                <p>Your session has been terminated and all associated tokens have been securely invalidated.</p>
            </div>
            
            <div class="info-card next-steps">
                <h3>📱 Next Steps</h3>
                <p>You can safely close this window or navigate back to your application. For complete security, consider closing your browser.</p>
            </div>
        </div>
    </div>
</body>
</html>`

	w.Write([]byte(html))
	s.logger.Info("Logout success page displayed")
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
