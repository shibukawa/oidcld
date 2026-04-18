package main

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestResolveServePort(t *testing.T) {
	assert.Equal(t, "19000", resolveServePort("19000", false))
	assert.Equal(t, config.DefaultHTTPPort, resolveServePort("", false))
	assert.Equal(t, config.DefaultHTTPSPort, resolveServePort("", true))
}

func TestShouldUseHTTPSByDefault(t *testing.T) {
	t.Run("http issuer stays http", func(t *testing.T) {
		cfg := &config.Config{OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"}}
		assert.False(t, shouldUseHTTPSByDefault(cfg, "", ""))
	})

	t.Run("https issuer enables https", func(t *testing.T) {
		cfg := &config.Config{OIDC: config.OIDCConfig{Issuer: "https://localhost:18443"}}
		assert.True(t, shouldUseHTTPSByDefault(cfg, "", ""))
	})

	t.Run("autocert enables https", func(t *testing.T) {
		cfg := &config.Config{
			OIDC:     config.OIDCConfig{Issuer: "http://localhost:18888"},
			Autocert: &config.AutocertConfig{Enabled: true},
		}
		assert.True(t, shouldUseHTTPSByDefault(cfg, "", ""))
	})

	t.Run("explicit certs enable https", func(t *testing.T) {
		assert.True(t, shouldUseHTTPSByDefault(nil, "cert.pem", "key.pem"))
	})
}
