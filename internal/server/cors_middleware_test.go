package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

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
			Algorithm:     "RS256",
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
