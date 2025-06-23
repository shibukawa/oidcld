package server

import (
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestOIDCServer_SessionEnderInterface(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer: "http://localhost:18888",
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create a logger for the test
	logger := slog.Default()

	server, err := NewServer(cfg, privateKey, logger)
	assert.NoError(t, err)

	// Test that server implements SessionEnder interface
	var _ op.SessionEnder = server

	// Test SessionEnder methods
	assert.NotZero(t, server.Decoder())
	assert.NotZero(t, server.Storage())
	assert.Equal(t, "http://localhost:18888/logout/success", server.DefaultLogoutRedirectURI())

	ctx := t.Context()
	verifier := server.IDTokenHintVerifier(ctx)
	// verifier can be nil in our simplified implementation
	_ = verifier
}

func TestStorageAdapter_SessionManagement(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write"},
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	storage := NewStorageAdapter(cfg, privateKey)

	// Test session creation
	session := storage.createUserSession("user1", "client1")
	assert.Equal(t, "user1", session.UserID)
	assert.Equal(t, "client1", session.ClientID)
	assert.Equal(t, "user1:client1", session.SessionID)
	assert.NotZero(t, session.CreatedAt)
	assert.NotZero(t, session.LastActivity)

	// Test token tracking
	storage.trackTokenForSession("user1", "client1", "token1", "access_token")
	storage.trackTokenForSession("user1", "client1", "token2", "refresh_token")

	// Verify tokens are tracked
	session = storage.userSessions["user1:client1"]
	assert.Equal(t, []string{"token1"}, session.AccessTokens)
	assert.Equal(t, []string{"token2"}, session.RefreshTokens)

	// Test session termination
	storage.terminateUserSession("user1", "client1")

	// Verify session is removed
	_, exists := storage.userSessions["user1:client1"]
	assert.False(t, exists)
}

func TestStorageAdapter_TerminateSessionFromRequest(t *testing.T) {
	cfg := &config.Config{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	storage := NewStorageAdapter(cfg, privateKey)

	// Create a session
	storage.createUserSession("user1", "client1")
	storage.trackTokenForSession("user1", "client1", "token1", "access_token")

	// Test CanTerminateSessionFromRequest interface
	var _ op.CanTerminateSessionFromRequest = storage

	// Create end session request
	endSessionReq := &op.EndSessionRequest{
		UserID:      "user1",
		ClientID:    "client1",
		RedirectURI: "https://example.com/logout",
	}

	ctx := t.Context()
	redirectURI, err := storage.TerminateSessionFromRequest(ctx, endSessionReq)
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/logout", redirectURI)

	// Verify session is terminated
	_, exists := storage.userSessions["user1:client1"]
	assert.False(t, exists)
}

func TestOIDCServer_ValidatePostLogoutRedirectURI(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer: "http://localhost:18888",
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	logger := slog.Default()
	server, err := NewServer(cfg, privateKey, logger)
	assert.NoError(t, err)

	tests := []struct {
		name        string
		redirectURI string
		expectError bool
	}{
		{
			name:        "valid https URI",
			redirectURI: "https://example.com/logout",
			expectError: false,
		},
		{
			name:        "valid http URI",
			redirectURI: "http://localhost:3000/logout",
			expectError: false,
		},
		{
			name:        "empty URI (optional)",
			redirectURI: "",
			expectError: false,
		},
		{
			name:        "invalid scheme",
			redirectURI: "ftp://example.com/logout",
			expectError: true,
		},
		{
			name:        "relative URI",
			redirectURI: "/logout",
			expectError: true,
		},
		{
			name:        "malformed URI",
			redirectURI: "://invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.validatePostLogoutRedirectURI(tt.redirectURI)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStorageAdapter_SessionTokenTracking(t *testing.T) {
	cfg := &config.Config{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	storage := NewStorageAdapter(cfg, privateKey)

	// Track multiple tokens for different sessions
	storage.trackTokenForSession("user1", "client1", "access1", "access_token")
	storage.trackTokenForSession("user1", "client1", "refresh1", "refresh_token")
	storage.trackTokenForSession("user2", "client1", "access2", "access_token")

	// Verify sessions are created
	assert.Equal(t, 2, len(storage.userSessions))

	session1 := storage.userSessions["user1:client1"]
	assert.Equal(t, []string{"access1"}, session1.AccessTokens)
	assert.Equal(t, []string{"refresh1"}, session1.RefreshTokens)

	session2 := storage.userSessions["user2:client1"]
	assert.Equal(t, []string{"access2"}, session2.AccessTokens)
	assert.Equal(t, 0, len(session2.RefreshTokens))

	// Verify token index
	assert.Equal(t, "user1", storage.tokenIndex["access1"])
	assert.Equal(t, "user1", storage.tokenIndex["refresh1"])
	assert.Equal(t, "user2", storage.tokenIndex["access2"])
}

func TestStorageAdapter_InvalidateSessionTokens(t *testing.T) {
	cfg := &config.Config{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	storage := NewStorageAdapter(cfg, privateKey)

	// Create tokens in storage
	storage.tokens = map[string]*Token{
		"access1": {ID: "access1"},
		"access2": {ID: "access2"},
	}
	storage.refreshTokens = map[string]*RefreshToken{
		"refresh1": {ID: "refresh1"},
	}

	// Create session with tokens
	session := &UserSession{
		UserID:        "user1",
		ClientID:      "client1",
		AccessTokens:  []string{"access1", "access2"},
		RefreshTokens: []string{"refresh1"},
	}

	// Invalidate session tokens
	storage.invalidateSessionTokens(session)

	// Verify tokens are removed
	assert.Equal(t, 0, len(storage.tokens))
	assert.Equal(t, 0, len(storage.refreshTokens))
}

func TestStorageAdapter_MultipleSessionTermination(t *testing.T) {
	cfg := &config.Config{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	storage := NewStorageAdapter(cfg, privateKey)

	// Create multiple sessions for the same user
	storage.createUserSession("user1", "client1")
	storage.createUserSession("user1", "client2")
	storage.createUserSession("user2", "client1")

	// Track tokens
	storage.trackTokenForSession("user1", "client1", "token1", "access_token")
	storage.trackTokenForSession("user1", "client2", "token2", "access_token")
	storage.trackTokenForSession("user2", "client1", "token3", "access_token")

	// Terminate all sessions for user1
	storage.terminateUserSession("user1", "")

	// Verify only user1 sessions are terminated
	assert.Equal(t, 1, len(storage.userSessions))
	_, exists := storage.userSessions["user2:client1"]
	assert.True(t, exists)

	// Verify user1 sessions are gone
	_, exists = storage.userSessions["user1:client1"]
	assert.False(t, exists)
	_, exists = storage.userSessions["user1:client2"]
	assert.False(t, exists)
}

// Benchmark session creation
func BenchmarkStorageAdapter_CreateUserSession(b *testing.B) {
	cfg := &config.Config{}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	storage := NewStorageAdapter(cfg, privateKey)

	b.ResetTimer()
	for i := range b.N {
		userID := "user" + string(rune(i))
		clientID := "client1"
		storage.createUserSession(userID, clientID)
	}
}

// Benchmark token tracking
func BenchmarkStorageAdapter_TrackTokenForSession(b *testing.B) {
	cfg := &config.Config{}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	storage := NewStorageAdapter(cfg, privateKey)

	b.ResetTimer()
	for i := range b.N {
		tokenID := "token" + string(rune(i))
		storage.trackTokenForSession("user1", "client1", tokenID, "access_token")
	}
}

// Benchmark session termination
func BenchmarkStorageAdapter_TerminateUserSession(b *testing.B) {
	cfg := &config.Config{}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	storage := NewStorageAdapter(cfg, privateKey)

	// Pre-create sessions
	for i := range 1000 {
		userID := "user" + string(rune(i))
		storage.createUserSession(userID, "client1")
		storage.trackTokenForSession(userID, "client1", "token"+string(rune(i)), "access_token")
	}

	b.ResetTimer()
	for i := range b.N {
		userID := "user" + string(rune(i%1000))
		storage.terminateUserSession(userID, "client1")
	}
}
