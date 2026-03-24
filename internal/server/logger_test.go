package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/fatih/color"
	"github.com/shibukawa/oidcld/internal/config"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	originalColorOutput := color.Output
	reader, writer, err := os.Pipe()
	assert.NoError(t, err)
	os.Stdout = writer
	color.Output = writer

	defer func() {
		os.Stdout = originalStdout
		color.Output = originalColorOutput
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

func TestServerStartingShowsHTTPMetadataCompanionEndpoints(t *testing.T) {
	logger := NewLogger()
	output := captureStdout(t, func() {
		logger.ServerStarting(":18443", "https://oidc.localhost:18443", true, nil, ":18888", accessFilterStartupInfo{
			Enabled:          true,
			ExtraAllowedIPs:  2,
			MaxForwardedHops: 1,
		})
	})

	assert.True(t, strings.Contains(output, "HTTP Metadata Companion"))
	assert.True(t, strings.Contains(output, ":18888"))
	assert.True(t, strings.Contains(output, "Discovery, JWKS, Health Check only"))
	assert.True(t, strings.Contains(output, "enabled (extra allowlist: 2, max forwarded hops: 1)"))
	assert.True(t, strings.Contains(output, "http://oidc.localhost:18888/.well-known/openid-configuration"))
	assert.True(t, strings.Contains(output, "http://oidc.localhost:18888/keys"))
	assert.True(t, strings.Contains(output, "http://oidc.localhost:18888/health"))
}

func TestServerStartingShowsHTTPMetadataCompanionEndpointsForEntraID(t *testing.T) {
	logger := NewLogger()
	output := captureStdout(t, func() {
		logger.ServerStarting(
			":18443",
			"https://oidc.localhost:18443/12345678-1234-1234-1234-123456789abc/v2.0",
			true,
			&config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
			":18888",
			accessFilterStartupInfo{Enabled: true},
		)
	})

	assert.True(t, strings.Contains(output, "http://oidc.localhost:18888/{tenant}/v2.0/.well-known/openid-configuration"))
	assert.True(t, strings.Contains(output, "http://oidc.localhost:18888/{tenant}/discovery/v2.0/keys"))
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

func TestRequestLogWithCORSShowsOriginDetails(t *testing.T) {
	logger := NewLogger()
	output := captureStdout(t, func() {
		logger.RequestLogWithCORS(http.MethodGet, "/userinfo", http.StatusOK, 25*time.Millisecond, "https://app.localhost:3000", "https://app.localhost:3000")
	})

	assert.True(t, strings.Contains(output, "/userinfo"))
	assert.True(t, strings.Contains(output, "Origin:"))
	assert.True(t, strings.Contains(output, "https://app.localhost:3000"))
	assert.True(t, strings.Contains(output, "CORS:"))
}
