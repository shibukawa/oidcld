package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestValidateClientCredentials(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		expectError  bool
	}{
		{
			name:         "valid credentials",
			clientID:     "test-client",
			clientSecret: "test-secret",
			expectError:  false,
		},
		{
			name:         "empty client ID",
			clientID:     "",
			clientSecret: "test-secret",
			expectError:  true,
		},
		{
			name:         "empty client secret",
			clientID:     "test-client",
			clientSecret: "",
			expectError:  true,
		},
		{
			name:         "both empty",
			clientID:     "",
			clientSecret: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientCredentials(tt.clientID, tt.clientSecret)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewClientCredentialsClient(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
			ExpiredIn:   3600,
		},
	}

	client := NewClientCredentialsClient("test-client", "test-secret", cfg)

	// Test basic properties
	assert.Equal(t, "test-client", client.GetID())
	assert.Equal(t, []oidc.GrantType{oidc.GrantTypeClientCredentials}, client.GrantTypes())
	assert.Equal(t, oidc.AuthMethodBasic, client.AuthMethod())
	assert.Equal(t, op.ApplicationTypeWeb, client.ApplicationType())
	assert.Equal(t, op.AccessTokenTypeJWT, client.AccessTokenType())
	assert.False(t, client.DevMode())
	assert.False(t, client.IDTokenUserinfoClaimsAssertion())

	// Test redirect URIs (should be empty for client credentials)
	assert.Equal(t, []string{}, client.RedirectURIs())
	assert.Equal(t, []string{}, client.PostLogoutRedirectURIs())
	// Test response types (should be empty for client credentials)
	assert.Equal(t, []oidc.ResponseType{}, client.ResponseTypes())

	// Test login URL (should be empty for client credentials)
	assert.Equal(t, "", client.LoginURL("test"))
}

func TestClient_ScopeValidation(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
		},
	}

	client := NewClientCredentialsClient("test-client", "test-secret", cfg)

	tests := []struct {
		name     string
		scope    string
		expected bool
	}{
		{
			name:     "valid scope - read",
			scope:    "read",
			expected: true,
		},
		{
			name:     "valid scope - write",
			scope:    "write",
			expected: true,
		},
		{
			name:     "valid scope - admin",
			scope:    "admin",
			expected: true,
		},
		{
			name:     "invalid scope",
			scope:    "invalid",
			expected: false,
		},
		{
			name:     "empty scope",
			scope:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.IsScopeAllowed(tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_ScopeValidation_NoValidScopes(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{}, // No valid scopes configured
		},
	}

	client := NewClientCredentialsClient("test-client", "test-secret", cfg)

	// Should reject all scopes when no valid scopes are configured
	assert.False(t, client.IsScopeAllowed("read"))
	assert.False(t, client.IsScopeAllowed("write"))
	assert.False(t, client.IsScopeAllowed("admin"))
}

func TestUpdateClientCredentialsClient(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write"},
		},
	}
	client := NewClientCredentialsClient("test-client", "test-secret", cfg)

	restrictFunc := client.RestrictAdditionalAccessTokenScopes()

	tests := []struct {
		name            string
		requestedScopes []string
		expectedScopes  []string
	}{
		{
			name:            "all valid scopes",
			requestedScopes: []string{"read", "write"},
			expectedScopes:  []string{"read", "write"},
		},
		{
			name:            "mixed valid and invalid scopes",
			requestedScopes: []string{"read", "invalid", "write"},
			expectedScopes:  []string{"read", "write"},
		},
		{
			name:            "all invalid scopes",
			requestedScopes: []string{"invalid1", "invalid2"},
			expectedScopes:  nil,
		},
		{
			name:            "empty scopes",
			requestedScopes: []string{},
			expectedScopes:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := restrictFunc(tt.requestedScopes)
			assert.Equal(t, tt.expectedScopes, result)
		})
	}
}

func TestUpdateClientCredentialsClient_NoValidScopes(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{}, // No valid scopes configured
		},
	}

	client := NewClientCredentialsClient("test-client", "test-secret", cfg)

	restrictFunc := client.RestrictAdditionalAccessTokenScopes()

	// Should reject all scopes when no valid scopes are configured
	result := restrictFunc([]string{"read", "write", "admin"})
	assert.Equal(t, ([]string)(nil), result)
}

func TestClientCredentialsTokenRequest(t *testing.T) {
	clientID := "test-client"
	scopes := []string{"read", "write"}
	audience := []string{"test-audience"}

	tokenReq := NewClientCredentialsTokenRequest(clientID, scopes, audience)

	assert.Equal(t, clientID, tokenReq.GetSubject())
	assert.Equal(t, scopes, tokenReq.GetScopes())
	assert.Equal(t, audience, tokenReq.GetAudience())
}

func TestStorageAdapter_ClientCredentials(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
		},
	}

	// Generate test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create storage adapter
	storage := NewStorageAdapter(cfg, privateKey)

	ctx := t.Context()

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		expectError  bool
	}{
		{
			name:         "valid client credentials",
			clientID:     "test-client",
			clientSecret: "test-secret",
			expectError:  false,
		},
		{
			name:         "empty client ID",
			clientID:     "",
			clientSecret: "test-secret",
			expectError:  true,
		},
		{
			name:         "empty client secret",
			clientID:     "test-client",
			clientSecret: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := storage.ClientCredentials(ctx, tt.clientID, tt.clientSecret)

			if tt.expectError {
				assert.Error(t, err)
				assert.Zero(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotZero(t, client)
				assert.Equal(t, tt.clientID, client.GetID())

				// Verify client supports client credentials grant
				grantTypes := client.GrantTypes()
				assert.True(t, len(grantTypes) > 0)
				assert.Equal(t, oidc.GrantTypeClientCredentials, grantTypes[0])
			}
		})
	}
}

func TestStorageAdapter_ClientCredentialsTokenRequest(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
		},
	}

	// Generate test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create storage adapter
	storage := NewStorageAdapter(cfg, privateKey)

	ctx := t.Context()
	clientID := "test-client"
	scopes := []string{"read", "write"}

	tokenReq, err := storage.ClientCredentialsTokenRequest(ctx, clientID, scopes)
	assert.NoError(t, err)
	assert.NotZero(t, tokenReq)

	// Verify token request properties
	assert.Equal(t, clientID, tokenReq.GetSubject())
	assert.Equal(t, scopes, tokenReq.GetScopes())
	// Audience is empty by default after config change
	assert.Equal(t, []string{}, tokenReq.GetAudience())
}

func TestStorageAdapter_ClientCredentialsIntegration(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
		},
	}

	// Generate test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create storage adapter
	storage := NewStorageAdapter(cfg, privateKey)

	ctx := t.Context()
	clientID := "test-client"
	clientSecret := "test-secret"
	requestedScopes := []string{"read", "write", "invalid"}

	// Test client credentials authentication
	client, err := storage.ClientCredentials(ctx, clientID, clientSecret)
	assert.NoError(t, err)
	assert.NotZero(t, client)

	// Test scope restriction
	restrictFunc := client.RestrictAdditionalAccessTokenScopes()
	allowedScopes := restrictFunc(requestedScopes)
	assert.Equal(t, []string{"read", "write"}, allowedScopes) // "invalid" should be filtered out

	// Test token request creation
	tokenReq, err := storage.ClientCredentialsTokenRequest(ctx, clientID, allowedScopes)
	assert.NoError(t, err)
	assert.NotZero(t, tokenReq)

	// Verify final token request
	assert.Equal(t, clientID, tokenReq.GetSubject())
	assert.Equal(t, allowedScopes, tokenReq.GetScopes())
	// Audience is empty by default after config change
	assert.Equal(t, []string{}, tokenReq.GetAudience())
}

// Test that the storage adapter implements the required interfaces
func TestStorageAdapter_InterfaceCompliance(_ *testing.T) {
	cfg := &config.Config{}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	storage := NewStorageAdapter(cfg, privateKey)

	// Verify that storage implements ClientCredentialsStorage interface
	var _ op.ClientCredentialsStorage = storage
}

// Benchmark client credentials validation
func BenchmarkValidateClientCredentials(b *testing.B) {
	clientID := "test-client"
	clientSecret := "test-secret"

	b.ResetTimer()
	for range b.N {
		_ = ValidateClientCredentials(clientID, clientSecret)
	}
}

// Benchmark client creation
func BenchmarkNewClientCredentialsClient(b *testing.B) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
		},
	}

	b.ResetTimer()
	for range b.N {
		_ = NewClientCredentialsClient("test-client", "test-secret", cfg)
	}
}

// Benchmark scope validation
func BenchmarkClient_IsScopeAllowed(b *testing.B) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write", "admin"},
		},
	}

	client := NewClientCredentialsClient("test-client", "test-secret", cfg)

	b.ResetTimer()
	for range b.N {
		_ = client.IsScopeAllowed("read")
	}
}
