package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestContentTypeLabelClassification(t *testing.T) {
	assert.Equal(t, "JSON", contentTypeLabel("application/json"))
	assert.Equal(t, "HTML", contentTypeLabel("text/html; charset=utf-8"))
	assert.Equal(t, "CSS", contentTypeLabel("text/css"))
	assert.Equal(t, "JS", contentTypeLabel("application/javascript"))
	assert.Equal(t, "Image", contentTypeLabel("image/png"))
	assert.Equal(t, "-", contentTypeLabel(""))
}

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
						{Path: "/api", Label: "api", TargetURL: upstream.URL, RewritePathPrefix: "/"},
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

func TestReverseProxy_DefaultVirtualHostMatchesUnconfiguredHostname(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost = r.Host
		_, _ = w.Write([]byte("default"))
	}))
	defer upstream.Close()

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://oidc.localhost:8443",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"localhost", "app.localhost"},
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Routes: []config.ReverseProxyRoute{
						{Path: "/", Label: "default-app", TargetURL: upstream.URL},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "https://app.localhost:8443/", nil)
	req.Host = "app.localhost:8443"
	req.TLS = &tls.ConnectionState{}
	res := httptest.NewRecorder()

	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, upstream.Listener.Addr().String(), upstreamHost)
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

func TestReverseProxy_OpenAPIMockReturnsExamplesAndPreferSelections(t *testing.T) {
	tempDir := t.TempDir()
	specPath := filepath.Join(tempDir, "mock.yaml")
	assert.NoError(t, os.WriteFile(specPath, []byte(`openapi: 3.0.3
info:
  title: Demo API
  version: "1.0"
paths:
  /items:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              examples:
                success:
                  value:
                    items:
                      - id: "one"
        "404":
          description: missing
          content:
            application/json:
              examples:
                missing:
                  value:
                    error: "missing"
`), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{{
				Host: "http://api.localhost",
				Routes: []config.ReverseProxyRoute{{
					Path:        "/api",
					OpenAPIFile: specPath,
					Mock: &config.ReverseProxyMockOptions{
						PreferExamples: true,
					},
					RewritePathPrefix: "/",
				}},
			}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/items", nil)
	req.Host = "api.localhost"
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "application/json", res.Header().Get("Content-Type"))
	assert.Equal(t, `{"items":[{"id":"one"}]}`, res.Body.String())

	preferReq := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/items", nil)
	preferReq.Host = "api.localhost"
	preferReq.Header.Set("Prefer", "code=404, example=missing")
	preferRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(preferRes, preferReq)
	assert.Equal(t, http.StatusNotFound, preferRes.Code)
	assert.Equal(t, `{"error":"missing"}`, preferRes.Body.String())
}

func TestReverseProxy_OpenAPIMockSynthesizesSchemaResponse(t *testing.T) {
	tempDir := t.TempDir()
	specPath := filepath.Join(tempDir, "mock.yaml")
	assert.NoError(t, os.WriteFile(specPath, []byte(`openapi: 3.0.3
info:
  title: Demo API
  version: "1.0"
paths:
  /items/{id}:
    get:
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id, enabled]
                properties:
                  id:
                    type: string
                  enabled:
                    type: boolean
`), 0o644))

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{{
				Host: "http://api.localhost",
				Routes: []config.ReverseProxyRoute{{
					Path:              "/api",
					OpenAPIFile:       specPath,
					RewritePathPrefix: "/",
				}},
			}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/items/42", nil)
	req.Host = "api.localhost"
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, `{"enabled":true,"id":"string"}`, res.Body.String())
}

func TestReverseProxy_GatewayRequiresValidJWTAndForwardsClaims(t *testing.T) {
	var forwardedSub string
	var forwardedScope string
	var forwardedAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedSub = r.Header.Get("X-Oidc-Sub")
		forwardedScope = r.Header.Get("X-Oidc-Scope")
		forwardedAuthorization = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{{
				Host: "http://api.localhost",
				Routes: []config.ReverseProxyRoute{{
					Path:      "/api",
					TargetURL: upstream.URL,
					Gateway: &config.ReverseProxyGateway{
						Required: config.ReverseProxyGatewayRequired{
							Enabled: true,
							Claims: map[string]any{
								"scope": "read",
								"aud":   "demo-client",
							},
						},
						ForwardClaimsAsHeaders: map[string]string{
							"sub":   "X-OIDC-Sub",
							"scope": "X-OIDC-Scope",
						},
					},
				}},
			}},
		},
	})

	unauthorizedReq := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/data", nil)
	unauthorizedReq.Host = "api.localhost"
	unauthorizedRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorizedRes, unauthorizedReq)
	assert.Equal(t, http.StatusUnauthorized, unauthorizedRes.Code)

	token, err := server.signJWT(jwt.MapClaims{
		"iss":   "http://localhost:18888",
		"sub":   "admin",
		"aud":   []string{"demo-client"},
		"scope": "read write",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	assert.NoError(t, err)

	authorizedReq := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/data", nil)
	authorizedReq.Host = "api.localhost"
	authorizedReq.Header.Set("Authorization", "Bearer "+token)
	authorizedRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorizedRes, authorizedReq)
	assert.Equal(t, http.StatusOK, authorizedRes.Code)
	assert.Equal(t, "admin", forwardedSub)
	assert.Equal(t, "read write", forwardedScope)
	assert.True(t, forwardedAuthorization != "")
	assert.True(t, forwardedAuthorization != "Bearer "+token)
}

func TestReverseProxyGatewayEvaluateClaimsReportsMissingScope(t *testing.T) {
	gateway := &compiledReverseProxyGateway{
		requiredEnabled: true,
		requiredClaims: map[string]any{
			"scope": "User.Read",
			"aud":   "test-client-id",
		},
	}

	check := gateway.evaluateClaims(jwt.MapClaims{
		"aud":       "test-client-id",
		"client_id": "test-client-id",
		"sub":       "admin",
	})

	assert.False(t, check.allowed())
	audClaims, ok := check.tokenClaims["aud"].([]string)
	assert.True(t, ok)
	assert.Equal(t, []string{"test-client-id"}, audClaims)
	assert.Equal(t, []string{"User.Read"}, check.missingScopes)
	assert.Equal(t, []string(nil), check.missingAudiences)
}

func TestReverseProxyGatewayEvaluateClaimsReportsMissingAudience(t *testing.T) {
	gateway := &compiledReverseProxyGateway{
		requiredEnabled: true,
		requiredClaims: map[string]any{
			"scope": "User.Read",
			"aud":   "expected-client",
		},
	}

	check := gateway.evaluateClaims(jwt.MapClaims{
		"aud":   "other-client",
		"scope": "User.Read",
	})

	assert.False(t, check.allowed())
	scopeClaims, ok := check.tokenClaims["scope"].([]string)
	assert.True(t, ok)
	assert.Equal(t, []string{"User.Read"}, scopeClaims)
	audClaims, ok := check.tokenClaims["aud"].([]string)
	assert.True(t, ok)
	assert.Equal(t, []string{"other-client"}, audClaims)
	assert.Equal(t, []string(nil), check.missingScopes)
	assert.Equal(t, []string{"expected-client"}, check.missingAudiences)
}

func TestReverseProxy_GatewayCanDisableAuthorizationReplay(t *testing.T) {
	var forwardedAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedAuthorization = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	replayDisabled := false
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{{
				Host: "http://api.localhost",
				Routes: []config.ReverseProxyRoute{{
					Path:      "/api",
					TargetURL: upstream.URL,
					Gateway: &config.ReverseProxyGateway{
						Required: config.ReverseProxyGatewayRequired{
							Enabled: true,
							Claims: map[string]any{
								"scope": "read",
							},
						},
						ReplayAuthorization: &replayDisabled,
					},
				}},
			}},
		},
	})

	token, err := server.signJWT(jwt.MapClaims{
		"iss":   "http://localhost:18888",
		"sub":   "admin",
		"aud":   []string{"demo-client"},
		"scope": "read write",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/data", nil)
	req.Host = "api.localhost"
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "Bearer "+token, forwardedAuthorization)
}

func TestReverseProxy_ReplaysOIDCLDAuthorizationWithoutGateway(t *testing.T) {
	var forwardedAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedAuthorization = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{{
				Host: "http://api.localhost",
				Routes: []config.ReverseProxyRoute{{
					Path:      "/api",
					TargetURL: upstream.URL,
				}},
			}},
		},
	})

	token, err := server.signJWT(jwt.MapClaims{
		"iss":   "http://localhost:18888",
		"sub":   "admin",
		"aud":   []string{"demo-client"},
		"scope": "read write",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://api.localhost/api/data", nil)
	req.Host = "api.localhost"
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.True(t, forwardedAuthorization != "")
	assert.True(t, forwardedAuthorization != "Bearer "+token)
}

func TestAdminHandler_ReverseProxyConfigIncludesMockAndGatewayMetadata(t *testing.T) {
	tempDir := t.TempDir()
	specPath := filepath.Join(tempDir, "mock.yaml")
	assert.NoError(t, os.WriteFile(specPath, []byte(`openapi: 3.0.3
info:
  title: Demo API
  version: "1.0"
paths:
  /items:
    get:
      responses:
        "200":
          description: ok
`), 0o644))

	server := createTestServer(&config.Config{
		OIDC:    config.OIDCConfig{Issuer: "http://localhost:18888"},
		Console: &config.ConsoleConfig{Port: "18889", BindAddress: "127.0.0.1"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{{
				Host: "http://api.localhost",
				Routes: []config.ReverseProxyRoute{{
					Path:              "/api",
					OpenAPIFile:       specPath,
					RewritePathPrefix: "/",
					Mock: &config.ReverseProxyMockOptions{
						PreferExamples: true,
						DefaultStatus:  "200",
					},
					Gateway: &config.ReverseProxyGateway{
						Required: config.ReverseProxyGatewayRequired{
							Enabled: true,
							Claims: map[string]any{
								"scope": "read",
								"aud":   "demo-client",
							},
						},
					},
				}},
			}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)

	var payload adminReverseProxyResponse
	assert.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	assert.Equal(t, 1, len(payload.Hosts))
	assert.Equal(t, 1, len(payload.Hosts[0].Routes))
	assert.Equal(t, "mock", payload.Hosts[0].Routes[0].RouteType)
	assert.Equal(t, specPath, payload.Hosts[0].Routes[0].Target)
	assert.True(t, payload.Hosts[0].Routes[0].GatewayEnabled)
	assert.Equal(t, map[string]any{"scope": "read", "aud": "demo-client"}, payload.Hosts[0].Routes[0].GatewayRequired)
	assert.True(t, payload.Hosts[0].Routes[0].GatewayReplayAuthorization)
	assert.True(t, payload.Hosts[0].Routes[0].MockPreferExamples)
	assert.Equal(t, "200", payload.Hosts[0].Routes[0].MockDefaultStatus)
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
	assert.Equal(t, filepath.Base(tempDir), configPayload.Hosts[0].Routes[0].Label)

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
	assert.Equal(t, filepath.Base(tempDir), logsPayload.Entries[0].RouteLabel)
	assert.Equal(t, "HTML", logsPayload.Entries[0].ContentTypeLabel)
}

func TestAdminHandler_ReverseProxyLogDetailCapturesRequestAndResponseBodies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := createTestServer(&config.Config{
		OIDC:    config.OIDCConfig{Issuer: "http://localhost:18888"},
		Console: &config.ConsoleConfig{Port: "18889", BindAddress: "127.0.0.1"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://api.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/submit", Label: "submit", TargetURL: upstream.URL},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://api.localhost/submit?expand=true", strings.NewReader(`{"hello":"world"}`))
	req.Host = "api.localhost"
	req.RemoteAddr = "127.0.0.1:41234"
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)

	logReq := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy/logs", nil)
	logReq.RemoteAddr = "127.0.0.1:41234"
	logRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(logRes, logReq)
	assert.Equal(t, http.StatusOK, logRes.Code)

	var logsPayload adminReverseProxyLogsResponse
	assert.NoError(t, json.Unmarshal(logRes.Body.Bytes(), &logsPayload))
	assert.Equal(t, 1, len(logsPayload.Entries))
	assert.Equal(t, "JSON", logsPayload.Entries[0].ContentTypeLabel)

	detailReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/console/api/reverse-proxy/logs/%d", logsPayload.Entries[0].ID), nil)
	detailReq.RemoteAddr = "127.0.0.1:41234"
	detailRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(detailRes, detailReq)
	assert.Equal(t, http.StatusOK, detailRes.Code)

	var detail reverseProxyLogDetail
	assert.NoError(t, json.Unmarshal(detailRes.Body.Bytes(), &detail))
	assert.Equal(t, "expand=true", detail.Request.Query)
	assert.Equal(t, `{"hello":"world"}`, detail.Request.Body.Text)
	assert.Equal(t, "json", detail.Request.Body.Kind)
	assert.Equal(t, "application/json", detail.Response.ContentType)
	assert.Equal(t, `{"ok":true}`, detail.Response.Body.Text)
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
	assert.Equal(t, "oidc", logsPayload.Entries[0].RouteLabel)

	detailReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/console/api/reverse-proxy/logs/%d", logsPayload.Entries[0].ID), nil)
	detailReq.RemoteAddr = "127.0.0.1:41234"
	detailRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(detailRes, detailReq)
	assert.Equal(t, http.StatusOK, detailRes.Code)

	var detailPayload reverseProxyLogDetail
	assert.NoError(t, json.Unmarshal(detailRes.Body.Bytes(), &detailPayload))
	assert.Equal(t, "https://oidc.localhost:18443", detailPayload.Target)
}

func TestAccessLogs_IgnoreConfiguredPaths(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC:    config.OIDCConfig{Issuer: "http://localhost:18888"},
		Console: &config.ConsoleConfig{Port: "18889", BindAddress: "127.0.0.1"},
		ReverseProxy: &config.ReverseProxyConfig{
			IgnoreLogPaths: []string{"/health", "/metrics*"},
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://app.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", TargetURL: "http://127.0.0.1:65535"},
					},
				},
			},
		},
	})

	healthReq := httptest.NewRequest(http.MethodGet, "http://localhost:18888/health", nil)
	healthReq.RemoteAddr = "127.0.0.1:41234"
	healthRes := httptest.NewRecorder()
	server.Handler().ServeHTTP(healthRes, healthReq)
	assert.Equal(t, http.StatusOK, healthRes.Code)

	logReq := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy/logs", nil)
	logReq.RemoteAddr = "127.0.0.1:41234"
	logRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(logRes, logReq)

	var logsPayload adminReverseProxyLogsResponse
	assert.NoError(t, json.Unmarshal(logRes.Body.Bytes(), &logsPayload))
	assert.Equal(t, 0, len(logsPayload.Entries))
}

func TestAdminHandler_ReverseProxyLogsReplay(t *testing.T) {
	var seenMethod string
	var seenPath string
	var seenBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		seenMethod = r.Method
		seenPath = r.URL.RequestURI()
		seenBody = string(bodyBytes)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	server := createTestServer(&config.Config{
		OIDC:    config.OIDCConfig{Issuer: "http://localhost:18888"},
		Console: &config.ConsoleConfig{Port: "18889", BindAddress: "127.0.0.1"},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "http://app.localhost",
					Routes: []config.ReverseProxyRoute{
						{
							Path:              "/api",
							Label:             "demo-api",
							TargetURL:         upstream.URL,
							RewritePathPrefix: "/",
						},
					},
				},
			},
		},
	})

	payload := []replayRequest{{
		Name:   "json-post",
		Scheme: "http",
		Host:   "app.localhost",
		Method: http.MethodPost,
		Path:   "/api/items",
		Query:  "a=1",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"Cookie":       {"hidden=true"},
		},
		Body: capturedBody{
			Kind:        "json",
			ContentType: "application/json",
			Text:        `{"hello":"world"}`,
		},
	}}
	bodyBytes, err := json.Marshal(payload)
	assert.NoError(t, err)

	replayReq := httptest.NewRequest(http.MethodPost, "/console/api/reverse-proxy/logs/replay", strings.NewReader(string(bodyBytes)))
	replayReq.RemoteAddr = "127.0.0.1:41234"
	replayReq.Header.Set("Content-Type", "application/json")
	replayRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(replayRes, replayReq)
	assert.Equal(t, http.StatusAccepted, replayRes.Code)
	assert.Equal(t, http.MethodPost, seenMethod)
	assert.Equal(t, "/items?a=1", seenPath)
	assert.Equal(t, `{"hello":"world"}`, seenBody)

	logReq := httptest.NewRequest(http.MethodGet, "/console/api/reverse-proxy/logs", nil)
	logReq.RemoteAddr = "127.0.0.1:41234"
	logRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(logRes, logReq)
	assert.Equal(t, http.StatusOK, logRes.Code)

	var logsPayload adminReverseProxyLogsResponse
	assert.NoError(t, json.Unmarshal(logRes.Body.Bytes(), &logsPayload))
	assert.Equal(t, 1, len(logsPayload.Entries))
	assert.Equal(t, "(REPLAY) /api/items", logsPayload.Entries[0].Path)
	assert.Equal(t, http.StatusCreated, logsPayload.Entries[0].StatusCode)

	detailReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/console/api/reverse-proxy/logs/%d", logsPayload.Entries[0].ID), nil)
	detailReq.RemoteAddr = "127.0.0.1:41234"
	detailRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(detailRes, detailReq)
	assert.Equal(t, http.StatusOK, detailRes.Code)

	var detailPayload reverseProxyLogDetail
	assert.NoError(t, json.Unmarshal(detailRes.Body.Bytes(), &detailPayload))
	assert.Equal(t, "Admin Console", detailPayload.RemoteAddr)
	assert.Equal(t, "/api/items", detailPayload.Request.Path)
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
	Entry        reverseProxyLogSummary
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
