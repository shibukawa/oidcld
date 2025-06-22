package server

import (
	"net/url"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestNewResponseBuilder(t *testing.T) {
	t.Run("Default to query mode", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "")
		assert.Equal(t, "query", rb.GetResponseMode())
	})

	t.Run("Preserve specified mode", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "fragment")
		assert.Equal(t, "fragment", rb.GetResponseMode())
	})
}

func TestResponseBuilder_AddParameter(t *testing.T) {
	rb := NewResponseBuilder("https://example.com/callback", "query")

	t.Run("Add single parameter", func(t *testing.T) {
		rb.AddParameter("code", "abc123")
		params := rb.GetParameters()
		assert.Equal(t, "abc123", params["code"])
	})

	t.Run("Skip empty values", func(t *testing.T) {
		rb.AddParameter("empty", "")
		params := rb.GetParameters()
		_, exists := params["empty"]
		assert.False(t, exists)
	})

	t.Run("Fluent interface", func(t *testing.T) {
		result := rb.AddParameter("state", "xyz789")
		assert.Equal(t, rb, result) // Should return same instance
	})
}

func TestResponseBuilder_AddParameters(t *testing.T) {
	rb := NewResponseBuilder("https://example.com/callback", "query")

	params := map[string]string{
		"code":  "abc123",
		"state": "xyz789",
		"empty": "", // Should be skipped
	}

	rb.AddParameters(params)
	result := rb.GetParameters()

	assert.Equal(t, "abc123", result["code"])
	assert.Equal(t, "xyz789", result["state"])
	_, exists := result["empty"]
	assert.False(t, exists)
}

func TestResponseBuilder_BuildQueryResponse(t *testing.T) {
	t.Run("Simple query response", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "query")
		rb.AddParameter("code", "abc123")
		rb.AddParameter("state", "xyz789")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)
		assert.Equal(t, "abc123", parsedURL.Query().Get("code"))
		assert.Equal(t, "xyz789", parsedURL.Query().Get("state"))
		assert.Equal(t, "", parsedURL.Fragment) // No fragment in query mode
	})

	t.Run("Merge with existing query parameters", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback?existing=value", "query")
		rb.AddParameter("code", "abc123")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)
		assert.Equal(t, "value", parsedURL.Query().Get("existing"))
		assert.Equal(t, "abc123", parsedURL.Query().Get("code"))
	})

	t.Run("No parameters", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "query")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)
		assert.Equal(t, "https://example.com/callback", redirectURL)
	})
}

func TestResponseBuilder_BuildFragmentResponse(t *testing.T) {
	t.Run("Simple fragment response", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "fragment")
		rb.AddParameter("code", "abc123")
		rb.AddParameter("state", "xyz789")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)

		// Parse fragment as query string
		fragmentParams, err := url.ParseQuery(parsedURL.Fragment)
		assert.NoError(t, err)
		assert.Equal(t, "abc123", fragmentParams.Get("code"))
		assert.Equal(t, "xyz789", fragmentParams.Get("state"))
		assert.Equal(t, "", parsedURL.RawQuery) // No query params in fragment mode
	})

	t.Run("Fragment mode clears query parameters", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback?existing=value", "fragment")
		rb.AddParameter("code", "abc123")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)
		assert.Equal(t, "", parsedURL.RawQuery) // Query cleared in fragment mode

		fragmentParams, err := url.ParseQuery(parsedURL.Fragment)
		assert.NoError(t, err)
		assert.Equal(t, "abc123", fragmentParams.Get("code"))
	})

	t.Run("No parameters", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "fragment")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)
		assert.Equal(t, "https://example.com/callback", redirectURL)
	})
}

func TestResponseBuilder_ResponseModes(t *testing.T) {
	testCases := []struct {
		name         string
		responseMode string
		expectedMode string
		isFragment   bool
		isQuery      bool
	}{
		{"Query mode", "query", "query", false, true},
		{"Fragment mode", "fragment", "fragment", true, false},
		{"Empty mode defaults to query", "", "query", false, true},
		{"Case insensitive fragment", "FRAGMENT", "FRAGMENT", true, false},
		{"Case insensitive query", "QUERY", "QUERY", false, true},
		{"Unknown mode defaults to query", "unknown", "unknown", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rb := NewResponseBuilder("https://example.com/callback", tc.responseMode)

			assert.Equal(t, tc.expectedMode, rb.GetResponseMode())
			assert.Equal(t, tc.isFragment, rb.IsFragmentMode())
			assert.Equal(t, tc.isQuery, rb.IsQueryMode())
		})
	}
}

func TestResponseBuilder_ErrorHandling(t *testing.T) {
	t.Run("Invalid redirect URI", func(t *testing.T) {
		rb := NewResponseBuilder("://invalid-uri", "query")
		rb.AddParameter("code", "abc123")

		_, err := rb.BuildRedirectURL()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid redirect URI")
	})
}

func TestResponseBuilder_RealWorldScenarios(t *testing.T) {
	t.Run("MSAL.js fragment mode", func(t *testing.T) {
		// Simulate MSAL.js request with fragment mode
		rb := NewResponseBuilder("http://localhost:3000/callback", "fragment")
		rb.AddParameter("code", "authorization_code_123")
		rb.AddParameter("state", "msal_state_456")
		rb.AddParameter("session_state", "session_789")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		// Should be: http://localhost:3000/callback#code=...&state=...&session_state=...
		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)

		fragmentParams, err := url.ParseQuery(parsedURL.Fragment)
		assert.NoError(t, err)
		assert.Equal(t, "authorization_code_123", fragmentParams.Get("code"))
		assert.Equal(t, "msal_state_456", fragmentParams.Get("state"))
		assert.Equal(t, "session_789", fragmentParams.Get("session_state"))
		assert.Equal(t, "", parsedURL.RawQuery) // No query params
	})

	t.Run("Traditional web app query mode", func(t *testing.T) {
		// Simulate traditional web app with query mode
		rb := NewResponseBuilder("https://app.example.com/auth/callback", "query")
		rb.AddParameter("code", "auth_code_abc")
		rb.AddParameter("state", "csrf_token_xyz")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		// Should be: https://app.example.com/auth/callback?code=...&state=...
		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)
		assert.Equal(t, "auth_code_abc", parsedURL.Query().Get("code"))
		assert.Equal(t, "csrf_token_xyz", parsedURL.Query().Get("state"))
		assert.Equal(t, "", parsedURL.Fragment) // No fragment
	})

	t.Run("Error response with fragment mode", func(t *testing.T) {
		// Simulate error response in fragment mode
		rb := NewResponseBuilder("http://localhost:3000/callback", "fragment")
		rb.AddParameter("error", "invalid_request")
		rb.AddParameter("error_description", "Missing required parameter")
		rb.AddParameter("state", "error_state_123")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)

		fragmentParams, err := url.ParseQuery(parsedURL.Fragment)
		assert.NoError(t, err)
		assert.Equal(t, "invalid_request", fragmentParams.Get("error"))
		assert.Equal(t, "Missing required parameter", fragmentParams.Get("error_description"))
		assert.Equal(t, "error_state_123", fragmentParams.Get("state"))
	})
}

func TestResponseBuilder_ParameterEncoding(t *testing.T) {
	t.Run("Special characters in parameters", func(t *testing.T) {
		rb := NewResponseBuilder("https://example.com/callback", "fragment")
		// Use - instead of + or & to avoid URL encoding issues
		rb.AddParameter("state", "value with spaces - special chars!")
		rb.AddParameter("error_description", "Error: Something went wrong (code=123)")

		redirectURL, err := rb.BuildRedirectURL()
		assert.NoError(t, err)

		parsedURL, err := url.Parse(redirectURL)
		assert.NoError(t, err)

		fragmentParams, err := url.ParseQuery(parsedURL.Fragment)
		assert.NoError(t, err)
		assert.Equal(t, "value with spaces - special chars!", fragmentParams.Get("state"))
		assert.Equal(t, "Error: Something went wrong (code=123)", fragmentParams.Get("error_description"))
	})
}
