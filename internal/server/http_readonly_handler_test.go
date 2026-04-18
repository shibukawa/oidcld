package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func newHTTPReadOnlyTestConfig() *config.Config {
	return &config.Config{
		OIDC: config.OIDCConfig{
			Issuer:      "https://localhost:8443",
			ExpiredIn:   3600,
			ValidScopes: []string{"openid", "profile", "email"},
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{"email": "test@example.com"},
			},
		},
	}
}

func TestReadOnlyHTTPHandler_AllowsMetadataAndRejectsInteractiveEndpoints(t *testing.T) {
	cfg := newHTTPReadOnlyTestConfig()
	useHTTPS, msg := cfg.PrepareForServe(&config.ServeOptions{Port: "8443"})
	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)

	server := createTestServer(cfg)
	handler := server.ReadOnlyHTTPHandler()

	for _, path := range []string{"/.well-known/openid-configuration", "/keys", "/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	assert.Equal(t, http.StatusNotFound, res.Code)

	req = httptest.NewRequest(http.MethodPost, "/.well-known/openid-configuration", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	assert.Equal(t, http.StatusMethodNotAllowed, res.Code)

	discoveryReq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	discoveryRes := httptest.NewRecorder()
	handler.ServeHTTP(discoveryRes, discoveryReq)
	assert.Equal(t, http.StatusOK, discoveryRes.Code)

	var discovery map[string]any
	err := json.Unmarshal(discoveryRes.Body.Bytes(), &discovery)
	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:8443", discovery["issuer"])
	assert.Equal(t, "https://localhost:8443/keys", discovery["jwks_uri"])
}

func TestReadOnlyHTTPHandler_AllowsEntraIDMetadataAliases(t *testing.T) {
	cfg := newEntraIDv2CORSConfig()
	useHTTPS, msg := cfg.PrepareForServe(&config.ServeOptions{Port: "8443"})
	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)

	server := createTestServer(cfg)
	handler := server.ReadOnlyHTTPHandler()

	paths := []string{
		"/12345678-1234-1234-1234-123456789abc/v2.0/.well-known/openid-configuration",
		"/common/v2.0/.well-known/openid-configuration",
		"/12345678-1234-1234-1234-123456789abc/discovery/v2.0/keys",
		"/common/discovery/v2.0/keys",
	}

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/authorize", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	assert.Equal(t, http.StatusNotFound, res.Code)
}
