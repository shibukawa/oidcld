package server

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestDiscoveryEndpointsForRequest_UsesConfiguredTenantForTenantlessV2Requests(t *testing.T) {
	endpoints := discoveryEndpointsForRequest(
		"https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0",
		&config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
		entraIDRequestInfo{Tenantless: true},
	)

	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/oauth2/v2.0/authorize", endpoints.Authorize)
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0/userinfo", endpoints.UserInfo)
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/discovery/v2.0/keys", endpoints.JWKS)
}

func TestDiscoveryEndpointsForRequest_UsesAliasTenantWhenProvided(t *testing.T) {
	endpoints := discoveryEndpointsForRequest(
		"https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0",
		&config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
		entraIDRequestInfo{Tenant: "common"},
	)

	assert.Equal(t, "https://oidc.localhost:8443/common/oauth2/v2.0/authorize", endpoints.Authorize)
	assert.Equal(t, "https://oidc.localhost:8443/common/v2.0/oauth/introspect", endpoints.Introspection)
	assert.Equal(t, "https://oidc.localhost:8443/common/discovery/v2.0/keys", endpoints.JWKS)
}
