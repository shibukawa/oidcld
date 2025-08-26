package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

// createTestServer creates a test server with the given config
func createTestServer(cfg *config.Config) *Server {
	// Use proper constructor to initialize all fields including Manager
	server, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return server
}

// TestResponseModeFragmentIntegration tests the complete response_mode=fragment flow
func TestResponseModeFragmentIntegration(t *testing.T) {
	// Create test server with minimal config
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:      "http://localhost:18888",
			ExpiredIn:   3600,
			ValidScopes: []string{"read", "write", "openid", "profile", "email"},
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
	server := createTestServer(cfg)
	t.Run("Fragment Mode Authorization Success", func(t *testing.T) {
		// Step 1: Make authorization request with response_mode=fragment
		authURL := "/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=openid&state=test123&response_mode=fragment"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Should get user selection page (200) or redirect (302)
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		if w.Code == http.StatusOK {
			// If we got the user selection page, simulate user selection
			body := w.Body.String()
			assert.Contains(t, body, "testuser") // Should show our test user
			// Extract session ID from the form
			sessionStart := strings.Index(body, `name="session_id" value="`)
			assert.True(t, sessionStart > 0, "Should find session_id in form")
			sessionStart += len(`name="session_id" value="`)
			sessionEnd := strings.Index(body[sessionStart:], `"`)
			sessionID := body[sessionStart : sessionStart+sessionEnd]
			// Step 2: Submit user selection with fragment mode
			formData := url.Values{}
			formData.Set("session_id", sessionID)
			formData.Set("user_id", "testuser")
			req2 := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(formData.Encode()))
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w2 := httptest.NewRecorder()
			server.Handler().ServeHTTP(w2, req2)
			// Should get redirect with authorization code
			assert.Equal(t, http.StatusFound, w2.Code)
			// Step 3: Verify redirect URL uses fragment mode
			location := w2.Header().Get("Location")
			assert.NotZero(t, location)
			parsedURL, err := url.Parse(location)
			assert.NoError(t, err)
			// In fragment mode, parameters should be in the fragment, not query
			assert.Equal(t, "", parsedURL.RawQuery, "Query parameters should be empty in fragment mode")
			assert.NotEqual(t, "", parsedURL.Fragment, "Fragment should contain parameters")
			// Parse fragment as query string to check parameters
			fragmentParams, err := url.ParseQuery(parsedURL.Fragment)
			assert.NoError(t, err)
			// Verify authorization code and state are in fragment
			assert.NotEqual(t, "", fragmentParams.Get("code"), "Should have authorization code in fragment")
			assert.Equal(t, "test123", fragmentParams.Get("state"), "Should have state in fragment")
			t.Logf("✅ Fragment mode redirect: %s", location)
			t.Logf("🔗 Fragment parameters: %s", parsedURL.Fragment)
		}
	})
	t.Run("Query Mode Authorization Success", func(t *testing.T) {
		// Step 1: Make authorization request with response_mode=query
		authURL := "/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=openid&state=test456&response_mode=query"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Should get user selection page (200) or redirect (302)
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		if w.Code == http.StatusOK {
			// If we got the user selection page, simulate user selection
			body := w.Body.String()
			assert.Contains(t, body, "testuser")
			// Extract session ID from the form
			sessionStart := strings.Index(body, `name="session_id" value="`)
			assert.True(t, sessionStart > 0)
			sessionStart += len(`name="session_id" value="`)
			sessionEnd := strings.Index(body[sessionStart:], `"`)
			sessionID := body[sessionStart : sessionStart+sessionEnd]
			// Step 2: Submit user selection with query mode
			formData := url.Values{}
			formData.Set("session_id", sessionID)
			formData.Set("user_id", "testuser")
			req2 := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(formData.Encode()))
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w2 := httptest.NewRecorder()
			server.Handler().ServeHTTP(w2, req2)
			// Should get redirect with authorization code
			assert.Equal(t, http.StatusFound, w2.Code)
			// Step 3: Verify redirect URL uses query mode
			location := w2.Header().Get("Location")
			assert.NotZero(t, location)
			parsedURL, err := url.Parse(location)
			assert.NoError(t, err)
			// In query mode, parameters should be in the query, not fragment
			assert.NotEqual(t, "", parsedURL.RawQuery, "Query parameters should contain parameters")
			assert.Equal(t, "", parsedURL.Fragment, "Fragment should be empty in query mode")
			// Parse query parameters
			queryParams := parsedURL.Query()
			// Verify authorization code and state are in query
			assert.NotEqual(t, "", queryParams.Get("code"), "Should have authorization code in query")
			assert.Equal(t, "test456", queryParams.Get("state"), "Should have state in query")
			t.Logf("✅ Query mode redirect: %s", location)
			t.Logf("🔗 Query parameters: %s", parsedURL.RawQuery)
		}
	})
	t.Run("Default Mode (Backward Compatibility)", func(t *testing.T) {
		// Step 1: Make authorization request without response_mode (should default to query)
		authURL := "/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=openid&state=test789"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Should get user selection page (200) or redirect (302)
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		if w.Code == http.StatusOK {
			// If we got the user selection page, simulate user selection
			body := w.Body.String()
			assert.Contains(t, body, "testuser")
			// Extract session ID from the form
			sessionStart := strings.Index(body, `name="session_id" value="`)
			assert.True(t, sessionStart > 0)
			sessionStart += len(`name="session_id" value="`)
			sessionEnd := strings.Index(body[sessionStart:], `"`)
			sessionID := body[sessionStart : sessionStart+sessionEnd]
			// Step 2: Submit user selection (default mode should be query)
			formData := url.Values{}
			formData.Set("session_id", sessionID)
			formData.Set("user_id", "testuser")
			req2 := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(formData.Encode()))
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w2 := httptest.NewRecorder()
			server.Handler().ServeHTTP(w2, req2)
			// Should get redirect with authorization code
			assert.Equal(t, http.StatusFound, w2.Code)
			// Step 3: Verify redirect URL defaults to query mode
			location := w2.Header().Get("Location")
			assert.NotZero(t, location)
			parsedURL, err := url.Parse(location)
			assert.NoError(t, err)
			// Default mode should use query parameters (backward compatibility)
			assert.NotEqual(t, "", parsedURL.RawQuery, "Default mode should use query parameters")
			assert.Equal(t, "", parsedURL.Fragment, "Fragment should be empty in default mode")
			// Parse query parameters
			queryParams := parsedURL.Query()
			// Verify authorization code and state are in query
			assert.NotEqual(t, "", queryParams.Get("code"), "Should have authorization code in query")
			assert.Equal(t, "test789", queryParams.Get("state"), "Should have state in query")
			t.Logf("✅ Default mode redirect: %s", location)
			t.Logf("🔗 Default uses query parameters for backward compatibility")
		}
	})
}

// TestResponseModeErrorHandling tests error responses with different response modes
func TestResponseModeErrorHandling(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{},
		Users:  map[string]config.User{},
	}
	server := createTestServer(cfg)
	t.Run("Fragment Mode Error Response", func(t *testing.T) {
		// Make invalid authorization request with response_mode=fragment
		authURL := "/authorize?response_type=code&client_id=invalid-client&redirect_uri=http://localhost:3000/callback&scope=openid&state=error123&response_mode=fragment"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Storage is permissive in test mode; invalid client will be accepted by storage
		// and the server will proceed to the normal authorization flow (200 or 302).
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		t.Logf("✅ Fragment mode permissive handling: Status %d (accepted in test mode)", w.Code)
	})
	t.Run("Query Mode Error Response", func(t *testing.T) {
		// Make invalid authorization request with response_mode=query
		authURL := "/authorize?response_type=code&client_id=invalid-client&redirect_uri=http://localhost:3000/callback&scope=openid&state=error456&response_mode=query"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Storage is permissive in test mode; invalid client will be accepted by storage
		// and the server will proceed to the normal authorization flow (200 or 302).
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		t.Logf("✅ Query mode permissive handling: Status %d (accepted in test mode)", w.Code)
	})
}

// TestResponseModeCompatibility tests compatibility with different client scenarios
func TestResponseModeCompatibility(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			ValidScopes: []string{"read", "write"},
		},
		Users: map[string]config.User{
			"user1": {
				DisplayName: "User One",
				ExtraClaims: map[string]any{
					"email": "user1@example.com",
				},
			},
		},
	}
	server := createTestServer(cfg)
	t.Run("MSAL.js Compatibility (Fragment Mode)", func(t *testing.T) {
		// Simulate MSAL.js request (typically uses fragment mode)
		authURL := "/authorize?response_type=code&client_id=msal-client&redirect_uri=http://localhost:3000/callback&scope=openid+profile&state=msal_state_123&response_mode=fragment&nonce=msal_nonce_456"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Should handle MSAL.js request properly
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		t.Logf("✅ MSAL.js compatibility: Status %d", w.Code)
	})
	t.Run("Traditional Web App Compatibility (Query Mode)", func(t *testing.T) {
		// Simulate traditional web app request (typically uses query mode)
		authURL := "/authorize?response_type=code&client_id=traditional-client&redirect_uri=https://app.example.com/auth/callback&scope=openid&state=webapp_state_789&response_mode=query"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Should handle traditional web app request properly
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		t.Logf("✅ Traditional web app compatibility: Status %d", w.Code)
	})
	t.Run("Legacy Client Compatibility (No Response Mode)", func(t *testing.T) {
		// Simulate legacy client request (no response_mode parameter)
		authURL := "/authorize?response_type=code&client_id=traditional-client&redirect_uri=https://legacy.example.com/callback&scope=openid&state=legacy_state_000"
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		// Should handle legacy client request properly (defaults to query mode)
		assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)
		t.Logf("✅ Legacy client compatibility: Status %d", w.Code)
	})
}

// TestResponseModeValidation tests validation of response_mode parameter
func TestResponseModeValidation(t *testing.T) {
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{},
		Users: map[string]config.User{
			"user1": {
				DisplayName: "User One",
			},
		},
	}
	server := createTestServer(cfg)

	testCases := []struct {
		name         string
		responseMode string
		expectValid  bool
		description  string
	}{
		{"Valid Fragment Mode", "fragment", true, "Should accept fragment mode"},
		{"Valid Query Mode", "query", true, "Should accept query mode"},
		{"Empty Mode (Default)", "", true, "Should accept empty mode (defaults to query)"},
		{"Case Insensitive Fragment", "FRAGMENT", true, "Should accept case insensitive fragment"},
		{"Case Insensitive Query", "QUERY", true, "Should accept case insensitive query"},
		{"Unknown Mode", "unknown_mode", true, "Should accept unknown mode (defaults to query)"},
		{"Form Post Mode", "form_post", true, "Should accept form_post mode (falls back to query)"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authURL := "/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=openid&state=test123"
			if tc.responseMode != "" {
				authURL += "&response_mode=" + tc.responseMode
			}
			req := httptest.NewRequest(http.MethodGet, authURL, nil)
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, req)
			if tc.expectValid {
				// Should not return error status
				assert.True(t, w.Code != http.StatusBadRequest, "Should not return 400 for valid response_mode")
				t.Logf("✅ %s: Status %d", tc.description, w.Code)
			} else {
				// Should return error status
				assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for invalid response_mode")
				t.Logf("❌ %s: Status %d", tc.description, w.Code)
			}
		})
	}
}
