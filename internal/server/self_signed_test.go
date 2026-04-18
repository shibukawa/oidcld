package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestEnsureManagedSelfSignedTLSAssetsCreatesFiles(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			CADir:       tempDir,
			Domains:     []string{"localhost", "*.dev.localhost"},
			CACertTTL:   "87600h",
			LeafCertTTL: "720h",
		},
	}

	bundle, err := ensureManagedSelfSignedTLSAssets(cfg)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(tempDir, "root-ca.pem"), bundle.CACertPath)
	for _, path := range []string{bundle.CACertPath, bundle.CAKeyPath} {
		_, statErr := os.Stat(path)
		assert.NoError(t, statErr)
	}
	for _, path := range []string{
		filepath.Join(tempDir, "oidcld-server.pem"),
		filepath.Join(tempDir, "oidcld-server-key.pem"),
		filepath.Join(tempDir, "oidcld-server-chain.pem"),
	} {
		_, statErr := os.Stat(path)
		assert.Error(t, statErr)
	}
}

func TestAdminHandler_CertificateAndDownloadEndpointsUseManagedAssets(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "/console/api/certificates", nil)
	req.RemoteAddr = "127.0.0.1:41234"
	res := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), "rootCA")
	assert.Contains(t, res.Body.String(), "leafCertificates")

	rootReq := httptest.NewRequest(http.MethodGet, "/console/api/downloads/root-ca.pem", nil)
	rootReq.RemoteAddr = "127.0.0.1:41234"
	rootRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(rootRes, rootReq)
	assert.Equal(t, http.StatusOK, rootRes.Code)
	assert.Contains(t, rootRes.Body.String(), "BEGIN CERTIFICATE")

	zipReq := httptest.NewRequest(http.MethodGet, "/console/api/downloads/certificate-installer.zip", nil)
	zipReq.RemoteAddr = "127.0.0.1:41234"
	zipRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(zipRes, zipReq)
	assert.Equal(t, http.StatusOK, zipRes.Code)
	assert.Equal(t, "application/zip", zipRes.Header().Get("Content-Type"))
	assert.Contains(t, zipRes.Header().Get("Content-Disposition"), "certificate-installer.zip")

	reader, err := zip.NewReader(bytes.NewReader(zipRes.Body.Bytes()), int64(zipRes.Body.Len()))
	assert.NoError(t, err)
	entries := map[string]bool{}
	caInfo, err := os.Stat(filepath.Join(tempDir, "root-ca.pem"))
	assert.NoError(t, err)
	for _, file := range reader.File {
		entries[file.Name] = true
		assert.Equal(t, caInfo.ModTime().UTC().Truncate(2*time.Second), file.Modified.UTC().Truncate(2*time.Second))
		switch file.Name {
		case "install.sh", "uninstall.sh":
			assert.Equal(t, os.FileMode(0755), file.Mode().Perm())
		case "root-ca.pem", "install.ps1", "uninstall.ps1":
			assert.Equal(t, os.FileMode(0644), file.Mode().Perm())
		}
	}
	for _, name := range []string{"root-ca.pem", "install.sh", "install.ps1", "uninstall.sh", "uninstall.ps1"} {
		assert.Equal(t, true, entries[name])
	}

	installReq := httptest.NewRequest(http.MethodGet, "/console/api/downloads/install.sh", nil)
	installReq.RemoteAddr = "127.0.0.1:41234"
	installRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(installRes, installReq)
	assert.Equal(t, http.StatusOK, installRes.Code)
	assert.Contains(t, installRes.Body.String(), "root-ca.pem")
	assert.Contains(t, installRes.Body.String(), "resolve_user_keychain()")
	assert.Contains(t, installRes.Body.String(), `security default-keychain -d user 2>/dev/null | tr -d '"' | xargs`)
	assert.NotContains(t, installRes.Body.String(), "/Library/Keychains/System.keychain")
	assert.Contains(t, installRes.Body.String(), "install_java()")
	assert.Contains(t, installRes.Body.String(), "keytool")
	assert.Contains(t, installRes.Body.String(), "install_nss()")
	assert.Contains(t, installRes.Body.String(), "certutil")
	assert.Contains(t, installRes.Body.String(), "/etc/pki/nssdb")
	assert.Contains(t, installRes.Body.String(), "$HOME/snap/firefox/common/.mozilla/firefox/")
	assert.Contains(t, installRes.Body.String(), "/opt/homebrew/opt/openjdk")
	assert.Contains(t, installRes.Body.String(), "/usr/local/opt/openjdk")
	assert.Contains(t, installRes.Body.String(), "$HOME/.sdkman/candidates/java/current/bin/keytool")
	assert.Contains(t, installRes.Body.String(), "$HOME/.sdkman/candidates/java/current/lib/security/cacerts")

	installPSReq := httptest.NewRequest(http.MethodGet, "/console/api/downloads/install.ps1", nil)
	installPSReq.RemoteAddr = "127.0.0.1:41234"
	installPSRes := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(installPSRes, installPSReq)
	assert.Equal(t, http.StatusOK, installPSRes.Code)
	assert.Contains(t, installPSRes.Body.String(), "keytool.exe")
	assert.Contains(t, installPSRes.Body.String(), "oidcld-development-root-ca")
	assert.Contains(t, installPSRes.Body.String(), `C:\Program Files\Java\*\lib\security\cacerts`)

	var certificatesPayload struct {
		LeafCertificates []struct {
			Organization string `json:"organization"`
			Domain       string `json:"domain"`
		} `json:"leafCertificates"`
	}
	err = json.Unmarshal(res.Body.Bytes(), &certificatesPayload)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(certificatesPayload.LeafCertificates))
	assert.Equal(t, "OIDCLD", certificatesPayload.LeafCertificates[0].Organization)
	assert.Equal(t, "localhost", certificatesPayload.LeafCertificates[0].Domain)
}

func TestManagedLeafIssuedDomainsUseIssuerHostname(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://oidc.dev.localhost:18443",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"localhost", "*.dev.localhost"},
		},
	}

	assert.Equal(t, []string{"oidc.dev.localhost"}, managedLeafIssuedDomains(cfg))
}

func TestValidateManagedIssuerDomainsRejectsMismatchedIssuer(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			Issuer: "https://issuer.example.com:18443",
		},
		CertificateAuthority: &config.CertificateAuthorityConfig{
			Domains: []string{"localhost", "*.dev.localhost"},
		},
	}

	err := validateManagedIssuerDomains(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `oidc.iss host "issuer.example.com" is not covered`)
}

func TestManagedLeafIssuedDomainsFallbackToLocalhost(t *testing.T) {
	cfg := &config.Config{}

	assert.Equal(t, []string{"localhost"}, managedLeafIssuedDomains(cfg))
}
