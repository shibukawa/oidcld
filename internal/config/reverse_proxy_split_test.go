package config

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestReverseProxyListenerScheme(t *testing.T) {
	t.Run("returns https for explicit https hosts", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{Issuer: "http://localhost:18888"},
			ReverseProxy: &ReverseProxyConfig{
				Hosts: []ReverseProxyHost{
					{Host: "https://app.localhost", Routes: []ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:3000"}}},
				},
			},
		}
		assert.NoError(t, cfg.Normalize())

		scheme, err := cfg.ReverseProxyListenerScheme()
		assert.NoError(t, err)
		assert.Equal(t, "https", scheme)
	})

	t.Run("rejects mixed explicit schemes", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{Issuer: "http://localhost:18888"},
			ReverseProxy: &ReverseProxyConfig{
				Hosts: []ReverseProxyHost{
					{Host: "https://app.localhost", Routes: []ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:3000"}}},
					{Host: "http://app2.localhost", Routes: []ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:4000"}}},
				},
			},
		}
		assert.NoError(t, cfg.Normalize())

		_, err := cfg.ReverseProxyListenerScheme()
		assert.True(t, errors.Is(err, ErrReverseProxyMixedListenerSchemes))
	})
}

func TestValidateSplitListenerPorts(t *testing.T) {
	t.Run("accepts explicit host port matching proxy port", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{Issuer: "https://localhost:18443"},
			ReverseProxy: &ReverseProxyConfig{
				Hosts: []ReverseProxyHost{
					{Host: "https://app.localhost:9443", Routes: []ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:3000"}}},
				},
			},
		}
		assert.NoError(t, cfg.Normalize())
		assert.NoError(t, cfg.ValidateSplitListenerPorts("8443", "9443", "8888"))
	})

	t.Run("rejects explicit host port mismatch", func(t *testing.T) {
		cfg := &Config{
			OIDC: OIDCConfig{Issuer: "https://localhost:18443"},
			ReverseProxy: &ReverseProxyConfig{
				Hosts: []ReverseProxyHost{
					{Host: "https://app.localhost:8443", Routes: []ReverseProxyRoute{{Path: "/", TargetURL: "http://127.0.0.1:3000"}}},
				},
			},
		}
		assert.NoError(t, cfg.Normalize())
		err := cfg.ValidateSplitListenerPorts("8443", "9443", "8888")
		assert.True(t, errors.Is(err, ErrReverseProxySplitHostPortMismatch))
	})

	t.Run("rejects split mode without reverse proxy hosts", func(t *testing.T) {
		cfg := &Config{OIDC: OIDCConfig{Issuer: "http://localhost:18888"}}
		assert.NoError(t, cfg.Normalize())
		err := cfg.ValidateSplitListenerPorts("8080", "9080", "8888")
		assert.True(t, errors.Is(err, ErrReverseProxySplitPortRequiresHosts))
	})
}
