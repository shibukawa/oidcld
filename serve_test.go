package main

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestResolveServePort(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("OIDCLD_CONTAINER", "")
	assert.Equal(t, "19000", resolveServePort("19000", false))
	assert.Equal(t, config.DefaultHTTPPort, resolveServePort("", false))
	assert.Equal(t, config.DefaultHTTPSPort, resolveServePort("", true))

	t.Setenv("PORT", "19191")
	assert.Equal(t, "19191", resolveServePort("", false))

	t.Setenv("PORT", "")
	t.Setenv("OIDCLD_CONTAINER", "1")
	assert.Equal(t, "80", resolveServePort("", false))
	assert.Equal(t, "443", resolveServePort("", true))
}

func TestResolveConsolePort(t *testing.T) {
	t.Setenv("CONSOLE_PORT", "")
	assert.Equal(t, "19999", resolveConsolePort("19999"))
	assert.Equal(t, "8888", resolveConsolePort(""))

	t.Setenv("CONSOLE_PORT", "29999")
	assert.Equal(t, "29999", resolveConsolePort(""))
}

func TestResolveProxyPort(t *testing.T) {
	t.Setenv("PROXY_PORT", "")
	assert.Equal(t, "17777", resolveProxyPort("17777"))
	assert.Equal(t, "", resolveProxyPort(""))

	t.Setenv("PROXY_PORT", "27777")
	assert.Equal(t, "27777", resolveProxyPort(""))
}

func TestIsContainerRuntime(t *testing.T) {
	t.Setenv("OIDCLD_CONTAINER", "")
	assert.False(t, isContainerRuntime())

	for _, value := range []string{"1", "true", "yes"} {
		t.Setenv("OIDCLD_CONTAINER", value)
		assert.True(t, isContainerRuntime())
	}
}

func TestShouldUseHTTPSByDefault(t *testing.T) {
	t.Run("http issuer stays http", func(t *testing.T) {
		cfg := &config.Config{OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"}}
		assert.False(t, shouldUseOIDCHTTPSByDefault(cfg, "", ""))
	})

	t.Run("https issuer enables https", func(t *testing.T) {
		cfg := &config.Config{OIDC: config.OIDCConfig{Issuer: "https://localhost:18443"}}
		assert.True(t, shouldUseOIDCHTTPSByDefault(cfg, "", ""))
	})

	t.Run("autocert enables https", func(t *testing.T) {
		cfg := &config.Config{
			OIDC:     config.OIDCConfig{Issuer: "http://localhost:18888"},
			Autocert: &config.AutocertConfig{Enabled: true},
		}
		assert.True(t, shouldUseOIDCHTTPSByDefault(cfg, "", ""))
	})

	t.Run("explicit certs enable https", func(t *testing.T) {
		assert.True(t, shouldUseOIDCHTTPSByDefault(nil, "cert.pem", "key.pem"))
	})
}

func TestShouldUseReverseProxyHTTPS(t *testing.T) {
	t.Run("no proxy port means disabled", func(t *testing.T) {
		useHTTPS, err := shouldUseReverseProxyHTTPS(&config.Config{}, "")
		assert.NoError(t, err)
		assert.False(t, useHTTPS)
	})

	t.Run("https proxy host enables https", func(t *testing.T) {
		cfg := &config.Config{
			OIDC: config.OIDCConfig{Issuer: "http://localhost:18888"},
			ReverseProxy: &config.ReverseProxyConfig{
				Hosts: []config.ReverseProxyHost{{Host: "https://app.localhost", Routes: []config.ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:3000"}}}},
			},
		}
		assert.NoError(t, cfg.Normalize())
		useHTTPS, err := shouldUseReverseProxyHTTPS(cfg, "9443")
		assert.NoError(t, err)
		assert.True(t, useHTTPS)
	})

	t.Run("http proxy host keeps http", func(t *testing.T) {
		cfg := &config.Config{
			OIDC: config.OIDCConfig{Issuer: "https://localhost:18443"},
			ReverseProxy: &config.ReverseProxyConfig{
				Hosts: []config.ReverseProxyHost{{Host: "http://app.localhost", Routes: []config.ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:3000"}}}},
			},
		}
		assert.NoError(t, cfg.Normalize())
		useHTTPS, err := shouldUseReverseProxyHTTPS(cfg, "9000")
		assert.NoError(t, err)
		assert.False(t, useHTTPS)
	})
}
