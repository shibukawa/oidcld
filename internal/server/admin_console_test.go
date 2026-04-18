package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestAdminHandler_StatusEndpointReturnsConfigSummary(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Issuer:              "https://localhost:18443",
			ValidScopes:         []string{"openid", "profile", "email"},
			PKCERequired:        false,
			NonceRequired:       false,
			ExpiredIn:           3600,
			AudienceClaimFormat: "string",
			RefreshTokenEnabled: true,
			RefreshTokenExpiry:  86400,
			EndSessionEnabled:   true,
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			CADir:       "./tls",
			Domains:     []string{"localhost", "*.dev.localhost"},
			CACertTTL:   "87600h",
			LeafCertTTL: "720h",
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	}

	server := createTestServer(cfg)
	req := httptest.NewRequest(http.MethodGet, "/console/api/status", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	var payload adminStatusResponse
	err := json.Unmarshal(res.Body.Bytes(), &payload)
	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:18443", payload.Issuer)
	assert.True(t, payload.HTTPSExpected)
	assert.Equal(t, 1, payload.UsersCount)
	assert.Equal(t, "18889", payload.AdminConsole.Port)
	assert.Equal(t, "oidc", payload.OIDC.Mode)
	assert.Equal(t, "self-signed", payload.OIDC.TLSSource)
	assert.Equal(t, false, payload.OIDC.PKCERequired)
	assert.Equal(t, false, payload.OIDC.NonceRequired)
	assert.Equal(t, 3600, payload.OIDC.ExpiredIn)
	assert.Equal(t, "string", payload.OIDC.AudienceClaimFormat)
	assert.Equal(t, true, payload.OIDC.RefreshTokenEnabled)
	assert.Equal(t, 86400, payload.OIDC.RefreshTokenExpiry)
	assert.Equal(t, true, payload.OIDC.EndSessionEnabled)
	assert.Equal(t, "https://localhost:18443/.well-known/openid-configuration", payload.OIDC.Endpoints.Discovery)
	assert.Equal(t, []string{"localhost", "*.dev.localhost"}, payload.SelfSignedTLS.Domains)
}

func TestAdminHandler_CertificatesReturnsEmptyLeafsOutsideSelfSigned(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer:            "https://localhost:18443",
			TLSCertFile:       "manual.pem",
			TLSKeyFile:        "manual-key.pem",
			ValidScopes:       []string{"openid"},
			ExpiredIn:         3600,
			EndSessionEnabled: true,
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/certificates", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	var payload struct {
		LeafCertificates []map[string]any `json:"leafCertificates"`
	}
	err := json.Unmarshal(res.Body.Bytes(), &payload)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(payload.LeafCertificates))
}

func TestAdminHandler_CertificatesIncludeReverseProxyManagedHosts(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer:      "https://oidc.localhost:18443",
			ValidScopes: []string{"openid"},
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			CADir:       "./tls",
			Domains:     []string{"oidc.localhost", "app.localhost"},
			CACertTTL:   "87600h",
			LeafCertTTL: "720h",
		},
		ReverseProxy: &config.ReverseProxyConfig{
			Hosts: []config.ReverseProxyHost{
				{
					Host: "https://app.localhost",
					Routes: []config.ReverseProxyRoute{
						{Path: "/", TargetURL: "http://app.localhost:80"},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/certificates", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	var payload struct {
		LeafCertificates []struct {
			Organization string `json:"organization"`
			Domain       string `json:"domain"`
		} `json:"leafCertificates"`
	}
	err := json.Unmarshal(res.Body.Bytes(), &payload)
	assert.NoError(t, err)
	assert.True(t, len(payload.LeafCertificates) >= 2)

	foundIssuer := false
	foundProxy := false
	for _, certificate := range payload.LeafCertificates {
		if certificate.Domain == "oidc.localhost" && certificate.Organization == "OIDCLD (OpenID Connect)" {
			foundIssuer = true
		}
		if certificate.Domain == "app.localhost" && certificate.Organization == "OIDCLD (Reverse Proxy)" {
			foundProxy = true
		}
	}
	assert.True(t, foundIssuer)
	assert.True(t, foundProxy)
}

func TestAdminHandler_OpenIDConnectUsersReturnsConfiguredClaims(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		Users: map[string]config.User{
			"alice": {
				DisplayName:      "Alice Example",
				ExtraValidScopes: []string{"profile", "email"},
				ExtraClaims: map[string]any{
					"email": "alice@example.com",
					"role":  "admin",
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/openid-connect/users", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)

	var payload adminUsersResponse
	err := json.Unmarshal(res.Body.Bytes(), &payload)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(payload.Users))
	assert.Equal(t, "alice", payload.Users[0].ID)
	assert.Equal(t, "Alice Example", payload.Users[0].DisplayName)
	assert.Equal(t, []string{"profile", "email"}, payload.Users[0].ExtraValidScopes)
	assert.Equal(t, "alice@example.com", payload.Users[0].ExtraClaims["email"])
	assert.Equal(t, "admin", payload.Users[0].ExtraClaims["role"])
}

func TestAdminHandler_RejectsNonLoopbackClients(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/status", nil)
	req.RemoteAddr = "192.168.1.20:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestAdminHandler_RejectsNonLoopbackClientsForOpenIDConnectUsers(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		Users: map[string]config.User{
			"admin": {DisplayName: "Administrator"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/openid-connect/users", nil)
	req.RemoteAddr = "192.168.1.20:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestAdminHandler_AllowsNonLoopbackClientsWhenConsoleBindsPublicly(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "0.0.0.0",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/api/status", nil)
	req.RemoteAddr = "192.168.1.20:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
}

func TestAdminHandler_IssueCertificateReturnsZipForWildcardDomain(t *testing.T) {
	tempDir := t.TempDir()
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			CADir:       tempDir,
			Domains:     []string{"localhost", "*.dev.localhost"},
			CACertTTL:   "87600h",
			LeafCertTTL: "720h",
		},
	})

	body := `{"organization":"Example Org","domainLabel":"admin","ttl":"720h","notBefore":"2026-04-18T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/certificates/issue", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:41234"
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "application/zip", res.Header().Get("Content-Type"))
	assert.Contains(t, res.Header().Get("Content-Disposition"), "certificate-admin.dev.localhost.zip")

	reader, err := zip.NewReader(bytes.NewReader(res.Body.Bytes()), int64(res.Body.Len()))
	assert.NoError(t, err)
	entries := map[string]bool{}
	for _, file := range reader.File {
		entries[file.Name] = true
	}
	assert.Equal(t, true, entries["certificate.pem"])
	assert.Equal(t, true, entries["private-key.pem"])
	assert.Equal(t, false, entries["chain.pem"])
	assert.Equal(t, false, entries["root-ca.pem"])

	listReq := httptest.NewRequest(http.MethodGet, "/console/api/certificates", nil)
	listReq.RemoteAddr = "127.0.0.1:41234"
	listRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(listRes, listReq)
	assert.Equal(t, http.StatusOK, listRes.Code)

	var payload struct {
		LeafCertificates []struct {
			Organization string `json:"organization"`
			Domain       string `json:"domain"`
		} `json:"leafCertificates"`
	}
	err = json.Unmarshal(listRes.Body.Bytes(), &payload)
	assert.NoError(t, err)
	assert.True(t, len(payload.LeafCertificates) >= 2)
	foundIssued := false
	for _, certificate := range payload.LeafCertificates {
		if certificate.Organization == "Example Org" && certificate.Domain == "admin.dev.localhost" {
			foundIssued = true
			break
		}
	}
	assert.True(t, foundIssued)
}

func TestAdminHandler_IssueCertificateRejectsInvalidInput(t *testing.T) {
	tempDir := t.TempDir()
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			CADir:       tempDir,
			Domains:     []string{"localhost", "*.dev.localhost"},
			CACertTTL:   "87600h",
			LeafCertTTL: "720h",
		},
	})

	cases := []string{
		`{"organization":"Example Org","domainLabel":"a.b","ttl":"720h","notBefore":"2026-04-18T00:00:00Z"}`,
		`{"organization":"Example Org","domainLabel":"admin","ttl":"bad","notBefore":"2026-04-18T00:00:00Z"}`,
		`{"organization":"Example Org","domainLabel":"admin","ttl":"720h","notBefore":"invalid"}`,
	}

	for _, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/console/api/certificates/issue", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:41234"
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(res, req)
		assert.Equal(t, http.StatusBadRequest, res.Code)
	}
}

func TestAdminHandler_IssueCertificateRejectsMissingWildcardDomain(t *testing.T) {
	tempDir := t.TempDir()
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			CADir:       tempDir,
			Domains:     []string{"localhost"},
			CACertTTL:   "87600h",
			LeafCertTTL: "720h",
		},
	})

	body := `{"organization":"Example Org","domainLabel":"admin","ttl":"720h","notBefore":"2026-04-18T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/console/api/certificates/issue", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:41234"
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusBadRequest, res.Code)
}

func TestAdminHandler_ServesFallbackWhenAssetsMissing(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusServiceUnavailable)
	assert.Contains(t, res.Body.String(), "OIDCLD Developer Console")
	body := res.Body.String()
	assert.True(t,
		containsAll(body, "Developer console assets were not found") || containsAll(body, "<div id=\"app\"></div>"),
	)
}

func TestAdminHandler_RedirectsRootToConsole(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "http://localhost:18888",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()

	server.AdminHandler().ServeHTTP(res, req)

	assert.Equal(t, http.StatusPermanentRedirect, res.Code)
	assert.Equal(t, "/console/", res.Header().Get("Location"))
}

func TestAdminHandler_ServesReadOnlyMetadataOnConsoleListenerForHTTPS(t *testing.T) {
	server := createTestServer(&config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		Console: &config.ConsoleConfig{
			Port:        "18889",
			BindAddress: "127.0.0.1",
		},
	})

	for _, path := range []string{"/.well-known/openid-configuration", "/keys", "/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:41234"
		res := httptest.NewRecorder()

		server.AdminHandler().ServeHTTP(res, req)

		assert.Equal(t, http.StatusOK, res.Code)
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}
