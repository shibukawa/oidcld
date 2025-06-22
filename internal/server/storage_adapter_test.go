package server

import (
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestStorageAdapter tests the corrected storage adapter for zitadel/oidc integration
func TestStorageAdapter_CreateAuthRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences: []string{"test-client"},
			ValidScopes:    []string{"read", "write"},
		},
	}, privateKey)

	ctx := t.Context()
	authReq := &oidc.AuthRequest{
		ClientID:            "test-client",
		RedirectURI:         "https://example.com/callback",
		Scopes:              []string{"openid", "profile", "read"},
		State:               "test-state",
		Nonce:               "test-nonce",
		CodeChallenge:       "test-challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}

	// Test successful creation
	result, err := adapter.CreateAuthRequest(ctx, authReq, "user1")
	assert.NoError(t, err)
	assert.NotEqual(t, "", result.GetID())
	assert.Equal(t, authReq.ClientID, result.GetClientID())
	assert.Equal(t, authReq.RedirectURI, result.GetRedirectURI())
	assert.Equal(t, authReq.Scopes, result.GetScopes())
	assert.Equal(t, "user1", result.GetSubject())

	// Test prompt=none case
	authReqNone := &oidc.AuthRequest{
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"openid"},
		Prompt:      []string{"none"},
	}

	_, err = adapter.CreateAuthRequest(ctx, authReqNone, "user1")
	assert.Error(t, err)
	// Should be a login required error
}

func TestStorageAdapter_AuthRequestByID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences: []string{"test-client"},
		},
	}, privateKey)

	ctx := t.Context()
	authReq := &oidc.AuthRequest{
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"openid", "profile"},
		State:       "test-state",
	}

	// Create auth request first
	result, err := adapter.CreateAuthRequest(ctx, authReq, "user1")
	assert.NoError(t, err)

	// Test successful retrieval
	retrieved, err := adapter.AuthRequestByID(ctx, result.GetID())
	assert.NoError(t, err)
	assert.Equal(t, result.GetID(), retrieved.GetID())
	assert.Equal(t, "test-client", retrieved.GetClientID())
	assert.Equal(t, "user1", retrieved.GetSubject())

	// Test non-existent request
	_, err = adapter.AuthRequestByID(ctx, "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStorageAdapter_SaveAuthCode_And_AuthRequestByCode(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences: []string{"test-client"},
		},
	}, privateKey)

	ctx := t.Context()
	authReq := &oidc.AuthRequest{
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"openid", "profile"},
	}

	// Create auth request and save code
	result, err := adapter.CreateAuthRequest(ctx, authReq, "user1")
	assert.NoError(t, err)

	err = adapter.SaveAuthCode(ctx, result.GetID(), "test-code-123")
	assert.NoError(t, err)

	// Test successful retrieval by code
	byCode, err := adapter.AuthRequestByCode(ctx, "test-code-123")
	assert.NoError(t, err)
	assert.Equal(t, result.GetID(), byCode.GetID())
	assert.Equal(t, "test-client", byCode.GetClientID())

	// Code should be deleted after use
	_, err = adapter.AuthRequestByCode(ctx, "test-code-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test non-existent code
	_, err = adapter.AuthRequestByCode(ctx, "non-existent-code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test saving code for non-existent auth request
	err = adapter.SaveAuthCode(ctx, "non-existent-req", "some-code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStorageAdapter_DeleteAuthRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences: []string{"test-client"},
		},
	}, privateKey)

	ctx := t.Context()
	authReq := &oidc.AuthRequest{
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"openid"},
	}

	// Create auth request
	result, err := adapter.CreateAuthRequest(ctx, authReq, "user1")
	assert.NoError(t, err)

	// Verify it exists
	_, err = adapter.AuthRequestByID(ctx, result.GetID())
	assert.NoError(t, err)

	// Delete the auth request
	err = adapter.DeleteAuthRequest(ctx, result.GetID())
	assert.NoError(t, err)

	// Verify it's deleted
	_, err = adapter.AuthRequestByID(ctx, result.GetID())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStorageAdapter_CreateAccessToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
	}, privateKey)

	ctx := t.Context()

	// Create a mock token request using auth request
	authReq := &oidc.AuthRequest{
		ClientID: "test-client",
		Scopes:   []string{"openid", "profile"},
	}

	result, err := adapter.CreateAuthRequest(ctx, authReq, "user1")
	assert.NoError(t, err)

	// Test successful token creation
	tokenID, expiration, err := adapter.CreateAccessToken(ctx, result)
	assert.NoError(t, err)
	assert.NotEqual(t, "", tokenID)
	assert.True(t, expiration.After(time.Now()))
	assert.True(t, expiration.Before(time.Now().Add(2*time.Hour)))

	// Verify token was stored
	adapter.lock.Lock()
	token, exists := adapter.tokens[tokenID]
	adapter.lock.Unlock()
	assert.True(t, exists)
	assert.Equal(t, "user1", token.Subject)
	assert.Equal(t, "test-client", token.Audience[0])
}

func TestStorageAdapter_CreateAccessAndRefreshTokens(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences:      []string{"test-client"},
			ExpiredIn:           3600,
			RefreshTokenEnabled: true,
			RefreshTokenExpiry:  86400,
		},
	}, privateKey)

	ctx := t.Context()

	// Create a mock token request
	authReq := &oidc.AuthRequest{
		ClientID: "test-client",
		Scopes:   []string{"openid", "profile", "offline_access"},
	}

	result, err := adapter.CreateAuthRequest(ctx, authReq, "user1")
	assert.NoError(t, err)

	// Test successful token creation
	accessTokenID, refreshTokenID, expiration, err := adapter.CreateAccessAndRefreshTokens(ctx, result, "")
	assert.NoError(t, err)
	assert.NotEqual(t, "", accessTokenID)
	assert.NotEqual(t, "", refreshTokenID)
	assert.True(t, expiration.After(time.Now()))

	// Verify access token was stored
	adapter.lock.Lock()
	accessToken, exists := adapter.tokens[accessTokenID]
	adapter.lock.Unlock()
	assert.True(t, exists)
	assert.Equal(t, "user1", accessToken.Subject)
	assert.Equal(t, "test-client", accessToken.Audience[0])

	// Verify refresh token was stored
	adapter.lock.Lock()
	refreshToken, exists := adapter.refreshTokens[refreshTokenID]
	adapter.lock.Unlock()
	assert.True(t, exists)
	assert.Equal(t, "user1", refreshToken.Subject)
	assert.Equal(t, "test-client", refreshToken.GetClientID())
}

func TestStorageAdapter_TokenRequestByRefreshToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences:      []string{"test-client"},
			RefreshTokenEnabled: true,
			RefreshTokenExpiry:  86400,
		},
	}, privateKey)

	ctx := t.Context()

	// Create a refresh token manually
	refreshTokenID := "refresh-token-123"
	refreshToken := &RefreshToken{
		ID:        refreshTokenID,
		Subject:   "user1",
		Audience:  []string{"test-client"},
		Scopes:    []string{"openid", "profile"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		AuthTime:  time.Now(),
	}

	adapter.lock.Lock()
	adapter.refreshTokens[refreshTokenID] = refreshToken
	adapter.lock.Unlock()

	// Test successful retrieval
	tokenReq, err := adapter.TokenRequestByRefreshToken(ctx, refreshTokenID)
	assert.NoError(t, err)
	assert.Equal(t, "test-client", tokenReq.GetClientID())
	assert.Equal(t, "user1", tokenReq.GetSubject())
	scopes := tokenReq.GetScopes()
	assert.True(t, slices.Contains(scopes, "openid"), "should contain openid scope")
	assert.True(t, slices.Contains(scopes, "profile"), "should contain profile scope")

	// Test non-existent refresh token
	_, err = adapter.TokenRequestByRefreshToken(ctx, "non-existent-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test expired refresh token
	expiredTokenID := "expired-refresh-token"
	expiredToken := &RefreshToken{
		ID:        expiredTokenID,
		Subject:   "user1",
		Audience:  []string{"test-client"},
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		AuthTime:  time.Now().Add(-2 * time.Hour),
	}

	adapter.lock.Lock()
	adapter.refreshTokens[expiredTokenID] = expiredToken
	adapter.lock.Unlock()

	_, err = adapter.TokenRequestByRefreshToken(ctx, expiredTokenID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")

	// Verify expired token was deleted
	adapter.lock.Lock()
	_, exists := adapter.refreshTokens[expiredTokenID]
	adapter.lock.Unlock()
	assert.False(t, exists)
}

func TestStorageAdapter_GetClientByID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidAudiences: []string{"test-client", "web-app"},
			ValidScopes:    []string{"read", "write", "admin"},
		},
	}, privateKey)

	ctx := t.Context()

	// Test successful client retrieval
	client, err := adapter.GetClientByClientID(ctx, "test-client")
	assert.NoError(t, err)
	assert.Equal(t, "test-client", client.GetID())
	redirectURIs := client.RedirectURIs()
	assert.True(t, len(redirectURIs) > 0, "should have redirect URIs configured")
	assert.True(t, slices.Contains(redirectURIs, "http://localhost:3000/callback"), "should contain test callback URI")
	assert.True(t, client.DevMode())
	assert.True(t, client.IDTokenUserinfoClaimsAssertion())

	// Test scopes
	assert.True(t, client.IsScopeAllowed("openid"))
	assert.True(t, client.IsScopeAllowed("profile"))
	assert.True(t, client.IsScopeAllowed("email"))
	assert.True(t, client.IsScopeAllowed("read"))
	assert.True(t, client.IsScopeAllowed("write"))
	assert.True(t, client.IsScopeAllowed("admin"))
	assert.False(t, client.IsScopeAllowed("unknown"))

	// Test grant types
	grantTypes := client.GrantTypes()

	// Check for all grant types
	assert.True(t, slices.Contains(grantTypes, oidc.GrantTypeCode), "should contain authorization_code grant")
	assert.True(t, slices.Contains(grantTypes, oidc.GrantTypeClientCredentials), "should contain client_credentials grant")
	assert.True(t, slices.Contains(grantTypes, oidc.GrantTypeRefreshToken), "should contain refresh_token grant")
	assert.True(t, slices.Contains(grantTypes, oidc.GrantTypeDeviceCode), "should contain device_code grant")

	// Test non-existent client
	_, err = adapter.GetClientByClientID(ctx, "non-existent-client")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client not found")
}

func TestStorageAdapter_SigningKey_And_KeySet(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{}, privateKey)

	ctx := t.Context()

	// Test signing key retrieval
	signingKey, err := adapter.SigningKey(ctx)
	assert.NoError(t, err)
	assert.NotZero(t, signingKey)
	assert.NotEqual(t, "", signingKey.ID())
	assert.Equal(t, privateKey, signingKey.Key().(*rsa.PrivateKey))

	// Test key set retrieval
	keySet, err := adapter.KeySet(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(keySet))

	key := keySet[0]
	assert.Equal(t, signingKey.ID(), key.ID())
	assert.Equal(t, "sig", key.Use())
	assert.Equal(t, &privateKey.PublicKey, key.Key().(*rsa.PublicKey))

	// Test signature algorithms
	algorithms, err := adapter.SignatureAlgorithms(ctx)
	assert.NoError(t, err)
	assert.True(t, slices.Contains(algorithms, signingKey.SignatureAlgorithm()), "should contain signing algorithm")
}

func TestStorageAdapter_Health(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	adapter := NewStorageAdapter(&config.Config{}, privateKey)

	ctx := t.Context()

	// Test health check
	err = adapter.Health(ctx)
	assert.NoError(t, err)
}
