package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func createLoginUITestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()

	if cfg.OIDCLD.AccessFilter == nil {
		cfg.OIDCLD.AccessFilter = &config.AccessFilterConfig{Enabled: false}
	}

	server, err := New(cfg)
	assert.NoError(t, err)
	return server
}

func createLoginAuthRequestID(t *testing.T, server *Server) string {
	t.Helper()

	authRequest, err := server.storage.CreateAuthRequest(t.Context(), &oidc.AuthRequest{
		ClientID:    "test-client",
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "profile", "email"},
		State:       "test-state",
	}, "")
	assert.NoError(t, err)
	return authRequest.GetID()
}

func TestLoginHandlerRendersEnvironmentBannerAndMarkdown(t *testing.T) {
	tempDir := t.TempDir()
	markdownPath := filepath.Join(tempDir, "login-info.md")
	err := os.WriteFile(markdownPath, []byte("## Helpful Links\n\n- [Runbook](https://example.com/runbook)\n- [Local Notes](./local-notes)\n- [Unsafe](javascript:alert(1))\n"), 0644)
	assert.NoError(t, err)

	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer: "http://localhost:18888",
			LoginUI: &config.LoginUIConfig{
				EnvTitle:         "Staging",
				InfoMarkdownFile: markdownPath,
			},
		},
		Users: map[string]config.User{
			"admin": {
				DisplayName: "Administrator",
				ExtraClaims: map[string]any{"email": "admin@example.com"},
			},
		},
	}
	server := createLoginUITestServer(t, cfg)
	authRequestID := createLoginAuthRequestID(t, server)

	request := httptest.NewRequest(http.MethodGet, "/login?authRequestID="+url.QueryEscape(authRequestID), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	body := response.Body.String()
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, body, "(Staging) OIDCLD: Login Page")
	assert.Contains(t, body, `href="https://github.com/shibukawa/oidcld"`)
	assert.Contains(t, body, cfg.OIDCLD.LoginUI.EffectiveAccentColor())
	assert.Contains(t, body, "login-main")
	assert.Contains(t, body, "users-panel")
	assert.Contains(t, body, "request-card")
	assert.Contains(t, body, "<h2>Helpful Links</h2>")
	assert.Contains(t, body, `href="https://example.com/runbook"`)
	assert.Contains(t, body, `href="./local-notes"`)
	assert.Contains(t, body, `href="#"`)
	assert.Contains(t, body, "@media (max-width: 960px)")
}

func TestLoginHandlerMissingMarkdownStillReturnsOK(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer: "http://localhost:18888",
			LoginUI: &config.LoginUIConfig{
				EnvTitle:         "Staging",
				InfoMarkdownFile: filepath.Join(t.TempDir(), "missing.md"),
			},
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	}
	server := createLoginUITestServer(t, cfg)
	authRequestID := createLoginAuthRequestID(t, server)

	request := httptest.NewRequest(http.MethodGet, "/login?authRequestID="+url.QueryEscape(authRequestID), nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	body := response.Body.String()
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, body, "(Staging) OIDCLD: Login Page")
	assert.Contains(t, body, "Request Information")
	assert.Contains(t, body, "Environment notes are currently unavailable.")
	assert.Contains(t, body, "Administrator")
}

func TestDeviceHandlerIgnoresLoginUIConfig(t *testing.T) {
	tempDir := t.TempDir()
	markdownPath := filepath.Join(tempDir, "login-info.md")
	err := os.WriteFile(markdownPath, []byte("## Helpful Links\n"), 0644)
	assert.NoError(t, err)

	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer: "http://localhost:18888",
			LoginUI: &config.LoginUIConfig{
				EnvTitle:         "Staging",
				InfoMarkdownFile: markdownPath,
			},
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	}
	server := createLoginUITestServer(t, cfg)

	request := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-EFGH", nil)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	body := response.Body.String()
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, body, "Device Verification")
	assert.NotContains(t, body, "Staging")
	assert.NotContains(t, body, "Helpful Links")
	assert.NotContains(t, body, "Environment notes are currently unavailable.")
}
