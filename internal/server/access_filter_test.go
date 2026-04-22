package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func newAccessFilterTestServer(t *testing.T, accessFilter *config.AccessFilterConfig) *Server {
	t.Helper()

	cfg := &config.Config{
		AccessFilter: accessFilter,
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	}

	server, err := New(cfg)
	assert.NoError(t, err)
	return server
}

func newRemoteRequest(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = remoteAddr
	return req
}

func TestAccessFilterAllowsDefaultLocalNetworks(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{Enabled: true})
	handler := server.Handler()

	for _, remoteAddr := range []string{
		"127.0.0.1:1234",
		"[::1]:1234",
		"[fd00::1234]:1234",
		"10.1.2.3:1234",
		"172.16.5.6:1234",
		"192.168.10.20:1234",
	} {
		req := newRemoteRequest(remoteAddr)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code, remoteAddr)
	}
}

func TestAccessFilterRejectsExternalPeerIP(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{Enabled: true})

	req := newRemoteRequest("8.8.8.8:1234")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
	assert.Contains(t, res.Body.String(), "access_filter denied this request because the client IP is not in the allowed local/private ranges.")
	assert.Contains(t, res.Body.String(), "remote_addr: 8.8.8.8:1234")
	assert.Contains(t, res.Body.String(), "forwarded: (not set)")
	assert.Contains(t, res.Body.String(), "x_forwarded_for: (not set)")
}

func TestAccessFilterAllowsExtraAllowedIP(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{
		Enabled:         true,
		ExtraAllowedIPs: []string{"203.0.113.10"},
	})

	req := newRemoteRequest("203.0.113.10:1234")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

func TestAccessFilterRejectsForwardedHeadersByDefault(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{Enabled: true})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("Forwarded", "for=203.0.113.10")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestAccessFilterAllowsForwardedHeadersWithinConfiguredHopLimit(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{
		Enabled:          true,
		MaxForwardedHops: 1,
	})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

func TestAccessFilterRejectsForwardedHeadersBeyondConfiguredHopLimit(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{
		Enabled:          true,
		MaxForwardedHops: 1,
	})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.20")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
	assert.Contains(t, res.Body.String(), "OIDCLD access_filter denied this request because the forwarded hop count exceeded the configured limit.")
	assert.Contains(t, res.Body.String(), "Configured max_forwarded_hops: 1")
	assert.Contains(t, res.Body.String(), "Observed effective hops: 2")
	assert.Contains(t, res.Body.String(), "X-Forwarded-For hops: 2")
}

func TestAccessFilterUsesMaxHopCountAcrossForwardHeaders(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{
		Enabled:          true,
		MaxForwardedHops: 1,
	})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("Forwarded", "for=203.0.113.10")
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.20")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestAccessFilterRejectsMalformedForwardedHeaders(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{
		Enabled:          true,
		MaxForwardedHops: 1,
	})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("Forwarded", "for=203.0.113.10,")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestAccessFilterAppliesToReadOnlyHTTPHandler(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{Enabled: true})

	req := newRemoteRequest("8.8.8.8:1234")
	res := httptest.NewRecorder()
	server.ReadOnlyHTTPHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestAccessFilterRejectsExternalPeerIPAsJSON(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{Enabled: true})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("Accept", "application/json")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
	assert.Equal(t, "application/json", res.Header().Get("Content-Type"))

	var payload map[string]any
	err := json.Unmarshal(res.Body.Bytes(), &payload)
	assert.NoError(t, err)
	assert.Equal(t, "access_filter_peer_not_allowed", payload["code"])
	assert.Equal(t, "peer_not_allowed", payload["reason"])
	details, ok := payload["details"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "(not set)", details["forwarded"])
	assert.Equal(t, "(not set)", details["x_forwarded_for"])
}

func TestAccessFilterPeerDeniedIncludesForwardedHeaderValues(t *testing.T) {
	server := newAccessFilterTestServer(t, &config.AccessFilterConfig{Enabled: true})

	req := newRemoteRequest("8.8.8.8:1234")
	req.Header.Set("Forwarded", "for=203.0.113.10;proto=https")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Host", "app.localhost")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Accept", "application/json")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)

	var payload map[string]any
	err := json.Unmarshal(res.Body.Bytes(), &payload)
	assert.NoError(t, err)
	details, ok := payload["details"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "for=203.0.113.10;proto=https", details["forwarded"])
	assert.Equal(t, "203.0.113.10", details["x_forwarded_for"])
	assert.Equal(t, "app.localhost", details["x_forwarded_host"])
	assert.Equal(t, "https", details["x_forwarded_proto"])
}
