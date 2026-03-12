package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func clearAutocertEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDCLD_ACME_DIRECTORY_URL", "")
	t.Setenv("OIDCLD_ACME_EMAIL", "")
	t.Setenv("OIDCLD_ACME_DOMAIN", "")
	t.Setenv("OIDCLD_ACME_CACHE_DIR", "")
	t.Setenv("OIDCLD_ACME_AGREE_TOS", "")
}

func testConfigPath(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	assert.NoError(t, err)
	return filepath.Join(wd, "testdata", name)
}

func TestHealthBuildURLKeepsConfiguredHTTPSPortInsideContainer(t *testing.T) {
	clearAutocertEnv(t)
	t.Setenv("OIDCLD_CONFIG", testConfigPath(t, "health-oidcld.yaml"))

	cmd := &HealthCmd{Config: "oidcld.yaml"}
	healthURL, isHTTPS, dialLocalhost, sniHost, err := cmd.buildHealthURL()

	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:8443/health", healthURL)
	assert.True(t, isHTTPS)
	assert.True(t, dialLocalhost)
	assert.Equal(t, "oidc.localhost", sniHost)
}

func TestHealthBuildURLKeepsConfiguredHTTPPortInsideContainer(t *testing.T) {
	clearAutocertEnv(t)
	t.Setenv("OIDCLD_CONFIG", testConfigPath(t, "health-http-oidcld.yaml"))

	cmd := &HealthCmd{Config: "oidcld.yaml"}
	healthURL, isHTTPS, dialLocalhost, sniHost, err := cmd.buildHealthURL()

	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:18888/health", healthURL)
	assert.False(t, isHTTPS)
	assert.True(t, dialLocalhost)
	assert.Equal(t, "oidc.localhost", sniHost)
}
