package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestAdminHandler_ReverseProxyLogsStreamSendsBacklogAndSync(t *testing.T) {
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

	makeStaticRequest(t, server, "http://spa.localhost/dashboard")
	makeStaticRequest(t, server, "http://spa.localhost/settings")

	adminServer := httptest.NewServer(server.AdminHandler())
	defer adminServer.Close()

	response, err := http.Get(adminServer.URL + "/console/api/reverse-proxy/logs/stream")
	assert.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "text/event-stream", strings.Split(response.Header.Get("Content-Type"), ";")[0])

	reader := bufio.NewReader(response.Body)
	first := readSSEEvent(t, reader)
	second := readSSEEvent(t, reader)
	syncEvent := readSSEEvent(t, reader)

	assert.Equal(t, "", first.Event)
	assert.Equal(t, int64(1), first.ID)
	assert.Equal(t, "/dashboard", first.Entry.Path)
	assert.Equal(t, "", second.Event)
	assert.Equal(t, int64(2), second.ID)
	assert.Equal(t, "/settings", second.Entry.Path)
	assert.Equal(t, "sync", syncEvent.Event)
	assert.True(t, syncEvent.SyncComplete)
}

func TestAdminHandler_ReverseProxyLogsStreamRespectsLastEventIDAndDisconnectCleanup(t *testing.T) {
	previousInterval := adminReverseProxyLogsHeartbeatInterval
	adminReverseProxyLogsHeartbeatInterval = 10 * time.Millisecond
	defer func() {
		adminReverseProxyLogsHeartbeatInterval = previousInterval
	}()

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

	makeStaticRequest(t, server, "http://spa.localhost/dashboard")
	makeStaticRequest(t, server, "http://spa.localhost/settings")

	adminServer := httptest.NewServer(server.AdminHandler())
	defer adminServer.Close()

	req, err := http.NewRequest(http.MethodGet, adminServer.URL+"/console/api/reverse-proxy/logs/stream", nil)
	assert.NoError(t, err)
	req.Header.Set("Last-Event-ID", "1")

	response, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	reader := bufio.NewReader(response.Body)

	backlog := readSSEEvent(t, reader)
	syncEvent := readSSEEvent(t, reader)
	heartbeat := readSSEEvent(t, reader)

	assert.Equal(t, int64(2), backlog.ID)
	assert.Equal(t, "/settings", backlog.Entry.Path)
	assert.Equal(t, "sync", syncEvent.Event)
	assert.True(t, syncEvent.SyncComplete)
	assert.True(t, heartbeat.IsHeartbeat)

	makeStaticRequest(t, server, "http://spa.localhost/profile")
	live := readSSEEvent(t, reader)
	assert.Equal(t, int64(3), live.ID)
	assert.Equal(t, "/profile", live.Entry.Path)

	assert.Equal(t, 1, len(server.reverseProxyLog.subscribers))
	assert.NoError(t, response.Body.Close())

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.reverseProxyLog.mu.RLock()
		count := len(server.reverseProxyLog.subscribers)
		server.reverseProxyLog.mu.RUnlock()
		if count == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected SSE subscriber cleanup after stream disconnect")
}

func makeStaticRequest(t *testing.T, server *Server, url string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Host = "spa.localhost"
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
}

type testSSEEvent struct {
	ID           int64
	Event        string
	Entry        reverseProxyLogEntry
	SyncComplete bool
	IsHeartbeat  bool
}

func readSSEEvent(t *testing.T, reader *bufio.Reader) testSSEEvent {
	t.Helper()

	event := testSSEEvent{}
	for {
		line, err := reader.ReadString('\n')
		assert.NoError(t, err)
		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			return event
		}
		if strings.HasPrefix(line, ":") {
			event.IsHeartbeat = true
			continue
		}
		switch {
		case strings.HasPrefix(line, "id: "):
			_, err := fmt.Sscanf(line, "id: %d", &event.ID)
			assert.NoError(t, err)
		case strings.HasPrefix(line, "event: "):
			event.Event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			payload := strings.TrimPrefix(line, "data: ")
			if event.Event == "sync" {
				var syncPayload struct {
					Complete bool `json:"complete"`
				}
				assert.NoError(t, json.Unmarshal([]byte(payload), &syncPayload))
				event.SyncComplete = syncPayload.Complete
				continue
			}
			assert.NoError(t, json.Unmarshal([]byte(payload), &event.Entry))
		}
	}
}
