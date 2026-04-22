package config

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestNormalizeIssuerForServeKeepsExistingNonRootPath(t *testing.T) {
	issuer := NormalizeIssuerForServe("https://oidc.localhost:8443/custom", "19000", &EntraIDConfig{
		TenantID: "12345678-1234-1234-1234-123456789abc",
		Version:  "v2",
	})

	assert.Equal(t, "https://oidc.localhost:8443/custom", issuer)
}

func TestIssuerPathPrefix(t *testing.T) {
	assert.Equal(t, "/tenant/v2.0", IssuerPathPrefix("https://oidc.localhost:8443/tenant/v2.0"))
	assert.Equal(t, "not a valid url", IssuerPathPrefix("not a valid url"))
	assert.Equal(t, "", IssuerPathPrefix("https://oidc.localhost:8443"))
}

func TestHTTPMetadataIssuer(t *testing.T) {
	issuer := HTTPMetadataIssuer("https://oidc.localhost:8443/tenant/v2.0", ":8080")
	assert.Equal(t, "http://oidc.localhost:8080/tenant/v2.0", issuer)

	invalid := HTTPMetadataIssuer("https://oidc.localhost:8443", "")
	assert.Equal(t, "", invalid)
}

func TestIssuerURLParts(t *testing.T) {
	scheme, host, port, ok := IssuerURLParts("https://oidc.localhost/tenant/v2.0")
	assert.True(t, ok)
	assert.Equal(t, "https", scheme)
	assert.Equal(t, "oidc.localhost", host)
	assert.Equal(t, DefaultHTTPSPort, port)

	scheme, host, port, ok = IssuerURLParts("http://127.0.0.1:19000")
	assert.True(t, ok)
	assert.Equal(t, "http", scheme)
	assert.Equal(t, "127.0.0.1", host)
	assert.Equal(t, "19000", port)

	invalidScheme, invalidHost, invalidPort, invalidOK := IssuerURLParts("localhost:19000")
	assert.Equal(t, "", invalidScheme)
	assert.Equal(t, "", invalidHost)
	assert.Equal(t, "", invalidPort)
	assert.False(t, invalidOK)
}
