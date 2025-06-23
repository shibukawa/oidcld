// Package server provides OpenID Connect server implementation.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Static errors for OIDC auth handler.
var (
	ErrUserNotFound                  = errors.New("user not found")
	ErrUserDoesNotHaveRequiredScopes = errors.New("user does not have required scopes")
)

// AuthHandler handles authentication flows for the OIDC server.
type AuthHandler struct {
	storage  *StorageAdapter
	config   *config.Config
	provider op.OpenIDProvider
}

// NewAuthHandler creates a new authentication handler.
func NewAuthHandler(storage *StorageAdapter, config *config.Config, provider op.OpenIDProvider) *AuthHandler {
	return &AuthHandler{
		storage:  storage,
		config:   config,
		provider: provider,
	}
}

// AuthenticateUser authenticates a user and completes the auth request.
func (h *AuthHandler) AuthenticateUser(ctx context.Context, authRequestID, userID string) error {
	// Get the auth request
	authReq, err := h.storage.AuthRequestByID(ctx, authRequestID)
	if err != nil {
		return fmt.Errorf("auth request not found: %w", err)
	}

	// Verify user exists
	user, exists := h.config.Users[userID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	// Check if user has required scopes
	if !h.userHasRequiredScopes(user, authReq.GetScopes()) {
		return ErrUserDoesNotHaveRequiredScopes
	}

	// Update the auth request with user information
	if oidcAuthReq, ok := authReq.(*AuthRequest); ok {
		oidcAuthReq.UserID = userID
		oidcAuthReq.AuthTime = time.Now()
		oidcAuthReq.done = true
	}

	return nil
}

// userHasRequiredScopes checks if user has the required scopes.
func (h *AuthHandler) userHasRequiredScopes(user config.User, requestedScopes []string) bool {
	// Standard scopes are always allowed
	standardScopes := map[string]bool{
		"openid":  true,
		"profile": true,
		"email":   true,
	}

	// Check each requested scope
	for _, scope := range requestedScopes {
		if standardScopes[scope] {
			continue // Standard scopes are always allowed
		}

		// Check if user has this custom scope
		if !slices.Contains(user.ExtraValidScopes, scope) {
			return false
		}
	}

	return true
}

// HandleAuthCallback handles the authentication callback.
func (h *AuthHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	userID := r.URL.Query().Get("userID")

	if authRequestID == "" || userID == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Authenticate the user
	ctx := r.Context()
	if err := h.AuthenticateUser(ctx, authRequestID, userID); err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusBadRequest)
		return
	}

	// Generate authorization code
	code, err := h.generateAuthCode()
	if err != nil {
		http.Error(w, "Failed to generate authorization code", http.StatusInternalServerError)
		return
	}

	// Save the authorization code
	if err := h.storage.SaveAuthCode(ctx, authRequestID, code); err != nil {
		http.Error(w, "Failed to save authorization code", http.StatusInternalServerError)
		return
	}

	// Get the auth request to build redirect URL
	authReq, err := h.storage.AuthRequestByID(ctx, authRequestID)
	if err != nil {
		http.Error(w, "Auth request not found", http.StatusInternalServerError)
		return
	}

	// Build redirect URL using ResponseBuilder with stored response mode
	builder := NewResponseBuilder(authReq.GetRedirectURI(), string(authReq.GetResponseMode()))
	builder.AddParameter("code", code)
	builder.AddParameter("state", authReq.GetState())

	// Build the final redirect URL
	redirectURL, err := builder.BuildRedirectURL()
	if err != nil {
		http.Error(w, "Failed to build redirect URL", http.StatusInternalServerError)
		return
	}

	// Redirect back to client
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// generateAuthCode generates a secure authorization code.
func (h *AuthHandler) generateAuthCode() (string, error) {
	// Use the same method as the original implementation
	return generateSecureToken(32)
}

// HandleDeviceAuth handles device authorization.
func (h *AuthHandler) HandleDeviceAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	userCode := r.FormValue("user_code")
	if userCode == "" {
		http.Error(w, "Missing user code", http.StatusBadRequest)
		return
	}

	// This would integrate with the device flow implementation
	// For now, show a simple success page
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Device Authorized - OIDC Test Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <h1 class="success">✓ Device Authorized</h1>
    <p>Your device has been successfully authorized.</p>
    <p>You can now return to your device and continue.</p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
