package server

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestMatchEntraIDRouteV2AliasDiscovery(t *testing.T) {
	route, matched, err := matchEntraIDRoute(
		"/common/v2.0/.well-known/openid-configuration",
		&config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
	)

	assert.NoError(t, err)
	assert.True(t, matched)
	assert.Equal(t, "/.well-known/openid-configuration", route.CanonicalPath)
	assert.Equal(t, "common", route.RequestInfo.Tenant)
	assert.False(t, route.RequestInfo.Tenantless)
}

func TestMatchEntraIDRouteRejectsMismatchedTenantGUID(t *testing.T) {
	_, matched, err := matchEntraIDRoute(
		"/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/v2.0/.well-known/openid-configuration",
		&config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v2"},
	)

	assert.True(t, matched)
	assert.Error(t, err)
	assert.Equal(t, "tenant \"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\": tenant does not match configured tenant_id", err.Error())
}

func TestEntraIDRoutesForRequestV1Tenantless(t *testing.T) {
	routes, ok := entraIDRoutesForRequest(
		"https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc",
		&config.EntraIDConfig{TenantID: "12345678-1234-1234-1234-123456789abc", Version: "v1"},
		entraIDRequestInfo{Tenantless: true},
	)

	assert.True(t, ok)
	assert.Equal(t, "https://oidc.localhost:8443/oauth2/authorize", routes.Authorize)
	assert.Equal(t, "https://oidc.localhost:8443/discovery/keys", routes.JWKS)
}
