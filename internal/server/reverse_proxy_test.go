package server

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestReverseProxy_ProxiesMatchedHostAndPath(t *testing.T) {
	var upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"app.localhost"},
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://app.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/api", TargetURL: upstream.URL, RewritePathPrefix: "/"},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/api/health", nil)
	req.Host = "app.localhost"
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusAccepted, res.Code)
	assert.Equal(t, "/health", upstreamPath)
	assert.Equal(t, "proxied", res.Body.String())
}

func TestReverseProxy_ServesStaticFilesWithSPAFallback(t *testing.T) {
	tempDir := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>spa</html>"), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"app.localhost"},
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
	})

	req := httptest.NewRequest(http.MethodGet, "http://spa.localhost/dashboard", nil)
	req.Host = "spa.localhost"
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), "spa")
}

func TestReverseProxy_DoesNotShadowReservedOIDCPaths(t *testing.T) {
	tempDir := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>static</html>"), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"app.localhost"},
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", StaticDir: tempDir, SPAFallback: true},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/openid-configuration", nil)
	req.Host = "localhost"
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), `"issuer"`)
	assert.False(t, res.Body.String() == "<html>static</html>")
}

func TestAdminHandler_ReverseProxyEndpointsExposeConfigAndLogs(t *testing.T) {
	tempDir := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(tempDir, "index.html"), []byte("<html>site</html>"), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		ReverseProxy: &config.ReverseProxyConfig{
			LogRetention: 64,
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://spa.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", StaticDir: tempDir, SPAFallback: true},
					},
				},
			},
		},
	})

	proxyReq := httptest.NewRequest(http.MethodGet, "http://spa.localhost/dashboard", nil)
	proxyReq.Host = "spa.localhost"
	proxyReq.RemoteAddr = "127.0.0.1:41234"
	proxyRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(proxyRes, proxyReq)
	assert.Equal(t, http.StatusOK, proxyRes.Code)

	configReq := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy", nil)
	configReq.RemoteAddr = "127.0.0.1:41234"
	configRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(configRes, configReq)
	assert.Equal(t, http.StatusOK, configRes.Code)

	var configPayload adminReverseProxyResponse
	assert.NoError(t, json.Unmarshal(configRes.Body.Bytes(), &configPayload))
	assert.Equal(t, 1, len(configPayload.Hosts))
	assert.Equal(t, "http://spa.localhost", configPayload.Hosts[0].Host)

	logReq := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy/logs", nil)
	logReq.RemoteAddr = "127.0.0.1:41234"
	logRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(logRes, logReq)
	assert.Equal(t, http.StatusOK, logRes.Code)

	var logsPayload adminReverseProxyLogsResponse
	assert.NoError(t, json.Unmarshal(logRes.Body.Bytes(), &logsPayload))
	assert.Equal(t, 1, len(logsPayload.Entries))
	assert.Equal(t, "static", logsPayload.Entries[0].RouteType)
	assert.Equal(t, "http://spa.localhost", logsPayload.Entries[0].RouteHost)
}

func TestReverseProxy_MatchesExplicitPortBeforePortlessFallback(t *testing.T) {
	exactUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("exact"))
	}))
	defer exactUpstream.Close()

	fallbackUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fallback"))
	}))
	defer fallbackUpstream.Close()

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"app.localhost"},
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "https://app.localhost:8443",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", TargetURL: exactUpstream.URL},
					},
				},
				{
					Host: "https://app.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", TargetURL: fallbackUpstream.URL},
					},
				},
			},
		},
	})

	exactReq := httptest.NewRequest(http.MethodGet, "https://app.localhost:8443/", nil)
	exactReq.Host = "app.localhost:8443"
	exactReq.TLS = &tls.ConnectionState{}
	exactRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(exactRes, exactReq)
	assert.Equal(t, "exact", exactRes.Body.String())

	fallbackReq := httptest.NewRequest(http.MethodGet, "https://app.localhost:9443/", nil)
	fallbackReq.Host = "app.localhost:9443"
	fallbackReq.TLS = &tls.ConnectionState{}
	fallbackRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(fallbackRes, fallbackReq)
	assert.Equal(t, "fallback", fallbackRes.Body.String())
}

func TestAdminHandler_TrafficLogsIncludeOIDCRequests(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer:      "https://oidc.localhost:18443",
			ValidScopes: []string{"openid"},
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
	})

	oidcReq := httptest.NewRequest(http.MethodGet, "https://oidc.localhost:18443/.well-known/openid-configuration", nil)
	oidcReq.Host = "oidc.localhost"
	oidcReq.RemoteAddr = "127.0.0.1:41234"
	oidcRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(oidcRes, oidcReq)
	assert.Equal(t, http.StatusOK, oidcRes.Code)

	logReq := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy/logs", nil)
	logReq.RemoteAddr = "127.0.0.1:41234"
	logRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(logRes, logReq)
	assert.Equal(t, http.StatusOK, logRes.Code)

	var logsPayload adminReverseProxyLogsResponse
	assert.NoError(t, json.Unmarshal(logRes.Body.Bytes(), &logsPayload))
	assert.Equal(t, 1, len(logsPayload.Entries))
	assert.Equal(t, "oidc", logsPayload.Entries[0].RouteType)
	assert.Equal(t, "oidc.localhost", logsPayload.Entries[0].RouteHost)
	assert.Equal(t, "/.well-known/openid-configuration", logsPayload.Entries[0].RoutePath)
	assert.Equal(t, "https://oidc.localhost:18443", logsPayload.Entries[0].Target)
}
