package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	assert.NoError(t, err)
	os.Stdout = writer

	defer func() {
		os.Stdout = originalStdout
	}()

	fn()
	assert.NoError(t, writer.Close())

	output, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.NoError(t, reader.Close())
	return string(output)
}

func TestServerStartingUsesTenantPlaceholderForEntraIDModes(t *testing.T) {
	tests := []struct {
		name              string
		issuer            string
		entraid           *config.EntraIDConfig
		expectedDiscovery string
		expectedAuth      string
		expectedUserInfo  string
		expectedHealth    string
	}{
		{
			name:              "v1",
			issuer:            "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc",
			entraid:           &config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v1"},
			expectedDiscovery: "https://oidc.localhost:8443/{tenant}/.well-known/openid-configuration",
			expectedAuth:      "https://oidc.localhost:8443/{tenant}/oauth2/authorize",
			expectedUserInfo:  "https://oidc.localhost:8443/{tenant}/userinfo",
			expectedHealth:    "https://oidc.localhost:8443/{tenant}/health",
		},
		{
			name:              "v2",
			issuer:            "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0",
			entraid:           &config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
			expectedDiscovery: "https://oidc.localhost:8443/{tenant}/v2.0/.well-known/openid-configuration",
			expectedAuth:      "https://oidc.localhost:8443/{tenant}/oauth2/v2.0/authorize",
			expectedUserInfo:  "https://oidc.localhost:8443/{tenant}/v2.0/userinfo",
			expectedHealth:    "https://oidc.localhost:8443/{tenant}/v2.0/health",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			display, ok := entraIDStartupDisplayForIssuer(tt.issuer, tt.entraid)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedDiscovery, display.Discovery)
			assert.Equal(t, tt.expectedAuth, display.Authorize)
			assert.Equal(t, tt.expectedUserInfo, display.UserInfo)
			if tt.name == "v2" {
				assert.Equal(t, "https://oidc.localhost:8443/{tenant}/v2.0/oauth/introspect", display.Introspection)
				assert.Equal(t, "https://oidc.localhost:8443/{tenant}/v2.0/revoke", display.Revocation)
			} else {
				assert.Equal(t, "https://oidc.localhost:8443/{tenant}/oauth/introspect", display.Introspection)
				assert.Equal(t, "https://oidc.localhost:8443/{tenant}/revoke", display.Revocation)
			}
			assert.Equal(t, tt.expectedHealth, display.HealthCheck)
			assert.Equal(t, []string{"common", "organizations", "customers", "contoso.onmicrosoft.com", "12345678-1234-1234-1234-123456789abc"}, display.Tenants)
		})
	}
}

func TestEntraIDRouteMiddlewareWarnsOnTenantlessRequest(t *testing.T) {
	server := &Server{
		config: &config.Config{
			EntraID: &config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
		},
		prettyLog: NewLogger(),
	}

	handler := server.entraIDRouteMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	output := captureStdout(t, func() {
		request := httptest.NewRequest(http.MethodGet, "/v2.0/.well-known/openid-configuration", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assert.Equal(t, http.StatusOK, response.Code)
	})

	assert.True(t, strings.Contains(output, "tenantless"))
	assert.True(t, strings.Contains(output, "Warning"))
}

func TestLoggingMiddlewareSkipsHealthRequests(t *testing.T) {
	server := &Server{
		config: &config.Config{
			OIDCLD: config.OIDCLDConfig{VerboseLogging: true},
		},
		prettyLog: NewLogger(),
	}

	handler := server.loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	healthOutput := captureStdout(t, func() {
		request := httptest.NewRequest(http.MethodGet, "/health", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assert.Equal(t, http.StatusOK, response.Code)
	})
	assert.Equal(t, "", strings.TrimSpace(healthOutput))

	regularOutput := captureStdout(t, func() {
		request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assert.Equal(t, http.StatusOK, response.Code)
	})
	assert.True(t, strings.Contains(regularOutput, "/userinfo"))
}
