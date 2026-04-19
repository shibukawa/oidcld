package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func newEntraIDv2CORSConfig() *config.Config {
	return &config.Config{
		AccessFilter: &config.AccessFilterConfig{Enabled: false},
		OIDC: config.OIDCConfig{
			Issuer:                    "https://oidc.localhost:8443",
			ExpiredIn:                 3600,
			ValidScopes:               []string{"openid", "profile", "email"},
			PKCERequired:              true,
			NonceRequired:             true,
			EndSessionEnabled:         true,
			EndSessionEndpointVisible: true,
			CORS: &config.CORSConfig{
				Enabled: true,
			},
		},
		EntraID: &config.EntraIDConfig{
			TenantID: "12345678-1234-1234-1234-123456789abc",
			Version:  "v2",
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

func TestHandleCORS_Defaults(t *testing.T) {
	handler := createCORSMiddleware(&config.CORSConfig{Enabled: true})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	assert.Equal(t, "*", res.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, PUT, PATCH, DELETE, OPTIONS", res.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization, Accept, Origin, X-Requested-With", res.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "true", res.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, http.StatusNoContent, res.Code)
}

func TestHandleCORS_PreflightWithDetailedConfig(t *testing.T) {
	handler := createCORSMiddleware(&config.CORSConfig{
		Enabled: true,
		Origins: []string{"https://app.localhost:3000"},
		Methods: []string{"GET", "POST", "OPTIONS"},
		Headers: []string{"Content-Type", "Authorization"},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("preflight request should not reach next handler")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/userinfo", nil)
	req.Header.Set("Origin", "https://app.localhost:3000")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "https://app.localhost:3000", res.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST, OPTIONS", res.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization", res.Header().Get("Access-Control-Allow-Headers"))
}

func TestOIDCCORSAppliesOnlyToOIDCTraffic(t *testing.T) {
	tempDir := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>site</html>"), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
			CORS: &config.CORSConfig{
				Enabled: true,
			},
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://spa.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", StaticDir: tempDir, SPAFallback: true},
					},
				},
			},
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	})

	oidcReq := httptest.NewRequest(http.MethodGet, "http://localhost/health", nil)
	oidcReq.Host = "localhost"
	oidcReq.Header.Set("Origin", "https://app.localhost:3000")
	oidcRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(oidcRes, oidcReq)

	proxyReq := httptest.NewRequest(http.MethodGet, "http://spa.localhost/", nil)
	proxyReq.Host = "spa.localhost"
	proxyReq.Header.Set("Origin", "https://app.localhost:3000")
	proxyRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(proxyRes, proxyReq)

	assert.Equal(t, "*", oidcRes.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "", proxyRes.Header().Get("Access-Control-Allow-Origin"))
}

func TestReverseProxyHostCORSAppliesOnlyToMatchedTraffic(t *testing.T) {
	tempDir := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>site</html>"), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://spa.localhost",
					CORS: &config.CORSConfig{
						Enabled: true,
						Origins: []string{"https://app.localhost:3000"},
						Methods: []string{"GET", "OPTIONS"},
						Headers: []string{"Content-Type"},
					},
					Routes: []config.ReverseProxyRoute{
						{Path: "/", StaticDir: tempDir, SPAFallback: true},
					},
				},
			},
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	})

	proxyReq := httptest.NewRequest(http.MethodGet, "http://spa.localhost/", nil)
	proxyReq.Host = "spa.localhost"
	proxyReq.Header.Set("Origin", "https://app.localhost:3000")
	proxyRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(proxyRes, proxyReq)

	oidcReq := httptest.NewRequest(http.MethodGet, "http://localhost/health", nil)
	oidcReq.Host = "localhost"
	oidcReq.Header.Set("Origin", "https://app.localhost:3000")
	oidcRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(oidcRes, oidcReq)

	assert.Equal(t, "https://app.localhost:3000", proxyRes.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, OPTIONS", proxyRes.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type", proxyRes.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "", oidcRes.Header().Get("Access-Control-Allow-Origin"))
}

func TestReverseProxyHostCORSPreflight(t *testing.T) {
	tempDir := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>site</html>"), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://spa.localhost",
					CORS: &config.CORSConfig{
						Enabled: true,
					},
					Routes: []config.ReverseProxyRoute{
						{Path: "/", StaticDir: tempDir, SPAFallback: true},
					},
				},
			},
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	})

	req := httptest.NewRequest(http.MethodOptions, "http://spa.localhost/", nil)
	req.Host = "spa.localhost"
	req.Header.Set("Origin", "https://app.localhost:3000")
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "*", res.Header().Get("Access-Control-Allow-Origin"))
}
