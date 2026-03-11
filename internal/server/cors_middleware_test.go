package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func newEntraIDv2CORSConfig() *config.Config {
	return &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:                    "https://oidc.localhost:8443",
			ExpiredIn:                 3600,
			ValidScopes:               []string{"openid", "profile", "email"},
			PKCERequired:              true,
			NonceRequired:             true,
			EndSessionEnabled:         true,
			EndSessionEndpointVisible: true,
		},
		EntraID: &config.EntraIDConfig{
			TenantID: "12345678-1234-1234-1234-123456789abc",
			Version:  "v2",
		},
		CORS: &config.CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"https://app.localhost:3000"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}
}

func newEntraIDv1CORSConfig() *config.Config {
	return &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:                    "https://oidc.localhost:8443",
			ExpiredIn:                 3600,
			ValidScopes:               []string{"openid", "profile", "email"},
			PKCERequired:              true,
			NonceRequired:             true,
			EndSessionEnabled:         true,
			EndSessionEndpointVisible: true,
		},
		EntraID: &config.EntraIDConfig{
			TenantID: "12345678-1234-1234-1234-123456789abc",
			Version:  "v1",
		},
		CORS: &config.CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"https://app.localhost:3000"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}
}

func newPreparedEntraIDv2Handler(t *testing.T) (*config.Config, http.Handler) {
	t.Helper()

	cfg := newEntraIDv2CORSConfig()
	useHTTPS, msg := cfg.PrepareForServe(&config.ServeOptions{Port: "8443"})
	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)

	server, err := New(cfg)
	assert.NoError(t, err)

	return cfg, server.Handler()
}

func newPreparedEntraIDv1Handler(t *testing.T) (*config.Config, http.Handler) {
	t.Helper()

	cfg := newEntraIDv1CORSConfig()
	useHTTPS, msg := cfg.PrepareForServe(&config.ServeOptions{Port: "8443"})
	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)

	server, err := New(cfg)
	assert.NoError(t, err)

	return cfg, server.Handler()
}

func TestCORSMiddleware(t *testing.T) {
	tests := []struct {
		name            string
		corsConfig      *config.CORSConfig
		method          string
		origin          string
		requestHeaders  string
		expectCORS      bool
		expectedOrigin  string
		expectedMethods string
		expectedHeaders string
	}{
		{
			name: "CORS disabled - no headers added",
			corsConfig: &config.CORSConfig{
				Enabled: false,
			},
			method:     "GET",
			origin:     "http://localhost:3000",
			expectCORS: false,
		},
		{
			name: "CORS enabled with wildcard origin",
			corsConfig: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
			method:          "GET",
			origin:          "http://localhost:3000",
			expectCORS:      true,
			expectedOrigin:  "*",
			expectedMethods: "GET, POST, OPTIONS",
			expectedHeaders: "Content-Type, Authorization",
		},
		{
			name: "CORS enabled with specific origin",
			corsConfig: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:3000", "https://example.com"},
				AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"Content-Type"},
			},
			method:          "GET",
			origin:          "http://localhost:3000",
			expectCORS:      true,
			expectedOrigin:  "http://localhost:3000",
			expectedMethods: "GET, POST",
			expectedHeaders: "Content-Type",
		},
		{
			name: "CORS enabled but origin not allowed",
			corsConfig: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"Content-Type"},
			},
			method:     "GET",
			origin:     "http://localhost:3000",
			expectCORS: false,
		},
		{
			name: "OPTIONS preflight request",
			corsConfig: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
			method:          "OPTIONS",
			origin:          "http://localhost:3000",
			requestHeaders:  "Content-Type, Authorization",
			expectCORS:      true,
			expectedOrigin:  "*",
			expectedMethods: "GET, POST, OPTIONS",
			expectedHeaders: "Content-Type, Authorization",
		},
		{
			name: "Default CORS configuration",
			corsConfig: &config.CORSConfig{
				Enabled: true,
			},
			method:          "GET",
			origin:          "http://localhost:3000",
			expectCORS:      true,
			expectedOrigin:  "*",
			expectedMethods: "GET, POST, OPTIONS",
			expectedHeaders: "Content-Type, Authorization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test response"))
			})

			// Create CORS middleware
			corsMiddleware := createCORSMiddleware(tt.corsConfig)
			handler := corsMiddleware(testHandler)

			// Create test request
			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.requestHeaders != "" {
				req.Header.Set("Access-Control-Request-Headers", tt.requestHeaders)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(w, req)

			// Check CORS headers
			if tt.expectCORS {
				assert.Equal(t, tt.expectedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, tt.expectedMethods, w.Header().Get("Access-Control-Allow-Methods"))
				assert.Equal(t, tt.expectedHeaders, w.Header().Get("Access-Control-Allow-Headers"))
				assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
			} else {
				assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Methods"))
				assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Headers"))
			}

			// OPTIONS requests should return 200 and not call the next handler
			if tt.method == "OPTIONS" && tt.expectCORS {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, "", w.Body.String()) // Empty body for preflight
			} else if tt.method != "OPTIONS" {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, "test response", w.Body.String())
			}
		})
	}
}

func TestCORSMiddlewareIntegration(t *testing.T) {
	// Create a minimal config with CORS enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:        "http://localhost:18888",
			ExpiredIn:     3600,
			ValidScopes:   []string{"read", "write"},
			PKCERequired:  false,
			NonceRequired: false,
		},
		CORS: &config.CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"http://localhost:3000"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server
	server, err := New(cfg)
	assert.NoError(t, err)

	// Get handler
	handler := server.Handler()

	// Test discovery endpoint with CORS
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))

	// Test preflight request
	req = httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check preflight response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv2PrefixedDiscovery(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:                    "https://oidc.localhost:8443",
			ExpiredIn:                 3600,
			ValidScopes:               []string{"openid", "profile", "email"},
			PKCERequired:              true,
			NonceRequired:             true,
			EndSessionEnabled:         true,
			EndSessionEndpointVisible: true,
		},
		EntraID: &config.EntraIDConfig{
			TenantID: "12345678-1234-1234-1234-123456789abc",
			Version:  "v2",
		},
		CORS: &config.CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"https://app.localhost:3000"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	useHTTPS, msg := cfg.PrepareForServe(&config.ServeOptions{Port: "8443"})
	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)

	server, err := New(cfg)
	assert.NoError(t, err)

	handler := server.Handler()
	req := httptest.NewRequest(http.MethodGet, "/12345678-1234-1234-1234-123456789abc/v2.0/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))

	var discovery map[string]any
	err = json.NewDecoder(w.Body).Decode(&discovery)
	assert.NoError(t, err)
	getString := func(key string) string {
		value, ok := discovery[key].(string)
		assert.True(t, ok)
		return value
	}

	assert.Equal(t, cfg.OIDCLD.Issuer, getString("issuer"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/authorize", getString("authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/token", getString("token_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/logout", getString("end_session_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/devicecode", getString("device_authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/discovery/v2.0/keys", getString("jwks_uri"))

	jwksURI, err := url.Parse(getString("jwks_uri"))
	assert.NoError(t, err)

	jwksRequest := httptest.NewRequest(http.MethodGet, jwksURI.Path, nil)
	jwksRequest.Header.Set("Origin", "https://app.localhost:3000")
	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, jwksRequest)

	assert.Equal(t, http.StatusOK, jwksResponse.Code)
	assert.Equal(t, "https://app.localhost:3000", jwksResponse.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv2AliasTenantDiscovery(t *testing.T) {
	cfg, handler := newPreparedEntraIDv2Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/common/v2.0/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))

	var discovery map[string]any
	err := json.NewDecoder(w.Body).Decode(&discovery)
	assert.NoError(t, err)
	getString := func(key string) string {
		value, ok := discovery[key].(string)
		assert.True(t, ok)
		return value
	}

	assert.Equal(t, cfg.OIDCLD.Issuer, getString("issuer"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/v2.0/authorize", getString("authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/v2.0/token", getString("token_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/v2.0/userinfo", getString("userinfo_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/v2.0/oauth/introspect", getString("introspection_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/v2.0/revoke", getString("revocation_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/v2.0/logout", getString("end_session_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/v2.0/devicecode", getString("device_authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/discovery/v2.0/keys", getString("jwks_uri"))

	jwksRequest := httptest.NewRequest(http.MethodGet, "/common/discovery/v2.0/keys", nil)
	jwksRequest.Header.Set("Origin", "https://app.localhost:3000")
	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, jwksRequest)

	assert.Equal(t, http.StatusOK, jwksResponse.Code)
	assert.Equal(t, "https://app.localhost:3000", jwksResponse.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv2TenantlessDiscovery(t *testing.T) {
	cfg, handler := newPreparedEntraIDv2Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/v2.0/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))

	var discovery map[string]any
	err := json.NewDecoder(w.Body).Decode(&discovery)
	assert.NoError(t, err)
	getString := func(key string) string {
		value, ok := discovery[key].(string)
		assert.True(t, ok)
		return value
	}

	assert.Equal(t, cfg.OIDCLD.Issuer, getString("issuer"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/authorize", getString("authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/token", getString("token_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0/userinfo", getString("userinfo_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0/oauth/introspect", getString("introspection_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0/revoke", getString("revocation_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/logout", getString("end_session_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/devicecode", getString("device_authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/discovery/v2.0/keys", getString("jwks_uri"))

	jwksRequest := httptest.NewRequest(http.MethodGet, "/discovery/v2.0/keys", nil)
	jwksRequest.Header.Set("Origin", "https://app.localhost:3000")
	jwksResponse := httptest.NewRecorder()
	handler.ServeHTTP(jwksResponse, jwksRequest)

	assert.Equal(t, http.StatusOK, jwksResponse.Code)
	assert.Equal(t, "https://app.localhost:3000", jwksResponse.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv2RejectsMismatchedTenantGUID(t *testing.T) {
	_, handler := newPreparedEntraIDv2Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/v2.0/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), "tenant"))
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv2AdvertisedUserInfoRoute(t *testing.T) {
	_, handler := newPreparedEntraIDv2Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/12345678-1234-1234-1234-123456789abc/v2.0/userinfo", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, w.Code != http.StatusNotFound)
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv1AliasTenantDiscovery(t *testing.T) {
	cfg, handler := newPreparedEntraIDv1Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/common/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))

	var discovery map[string]any
	err := json.NewDecoder(w.Body).Decode(&discovery)
	assert.NoError(t, err)
	getString := func(key string) string {
		value, ok := discovery[key].(string)
		assert.True(t, ok)
		return value
	}

	assert.Equal(t, cfg.OIDCLD.Issuer, getString("issuer"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/authorize", getString("authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/token", getString("token_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/userinfo", getString("userinfo_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth/introspect", getString("introspection_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/revoke", getString("revocation_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/logout", getString("end_session_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/devicecode", getString("device_authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/common/discovery/keys", getString("jwks_uri"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv1TenantlessDiscovery(t *testing.T) {
	cfg, handler := newPreparedEntraIDv1Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))

	var discovery map[string]any
	err := json.NewDecoder(w.Body).Decode(&discovery)
	assert.NoError(t, err)
	getString := func(key string) string {
		value, ok := discovery[key].(string)
		assert.True(t, ok)
		return value
	}

	assert.Equal(t, cfg.OIDCLD.Issuer, getString("issuer"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/authorize", getString("authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/token", getString("token_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/userinfo", getString("userinfo_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth/introspect", getString("introspection_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/revoke", getString("revocation_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/logout", getString("end_session_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/devicecode", getString("device_authorization_endpoint"))
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/discovery/keys", getString("jwks_uri"))
}

func TestCORSMiddlewareIntegrationWithEntraIDv1RejectsMismatchedTenantGUID(t *testing.T) {
	_, handler := newPreparedEntraIDv1Handler(t)
	req := httptest.NewRequest(http.MethodGet, "/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.True(t, strings.Contains(w.Body.String(), "tenant"))
	assert.Equal(t, "https://app.localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSConfigDefaults(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.CORSConfig
		expected *config.CORSConfig
	}{
		{
			name:   "nil config",
			config: nil,
			expected: &config.CORSConfig{
				Enabled: false,
			},
		},
		{
			name: "enabled with no other settings",
			config: &config.CORSConfig{
				Enabled: true,
			},
			expected: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
		},
		{
			name: "partial configuration",
			config: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:3000"},
			},
			expected: &config.CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"http://localhost:3000"},
				AllowedMethods: []string{"GET", "POST", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyCORSDefaults(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}
