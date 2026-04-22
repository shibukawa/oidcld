package server

import (
	"net/http"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

type oidcEndpointSet struct {
	Discovery           string
	Authorize           string
	Token               string
	UserInfo            string
	Introspection       string
	Revocation          string
	Logout              string
	DeviceAuthorization string
	JWKS                string
	HealthCheck         string
}

func defaultOIDCEndpoints(issuer string) oidcEndpointSet {
	return oidcEndpointSet{
		Discovery:           issuer + "/.well-known/openid-configuration",
		Authorize:           issuer + "/authorize",
		Token:               issuer + "/token",
		UserInfo:            issuer + "/userinfo",
		Introspection:       issuer + "/oauth/introspect",
		Revocation:          issuer + "/revoke",
		Logout:              issuer + "/end_session",
		DeviceAuthorization: issuer + "/device_authorization",
		JWKS:                issuer + "/keys",
		HealthCheck:         issuer + "/health",
	}
}

func oidcEndpointsForRequest(issuer string, entraid *config.EntraIDConfig, requestInfo entraIDRequestInfo) oidcEndpointSet {
	endpoints := defaultOIDCEndpoints(issuer)
	routes, ok := entraIDRoutesForRequest(issuer, entraid, requestInfo)
	if !ok {
		return endpoints
	}

	endpoints.Authorize = routes.Authorize
	endpoints.Token = routes.Token
	endpoints.UserInfo = routes.UserInfo
	endpoints.Introspection = routes.Introspection
	endpoints.Revocation = routes.Revocation
	endpoints.Logout = routes.Logout
	endpoints.DeviceAuthorization = routes.DeviceAuthorization
	endpoints.JWKS = routes.JWKS
	return endpoints
}

func discoveryRequestInfo(entraid *config.EntraIDConfig, requestInfo entraIDRequestInfo) entraIDRequestInfo {
	if requestInfo.Tenantless && entraid != nil {
		configuredTenant := strings.Trim(entraid.TenantID, "/")
		if configuredTenant != "" {
			requestInfo.Tenant = configuredTenant
			requestInfo.Tenantless = false
		}
	}
	return requestInfo
}

func discoveryEndpointsForRequest(issuer string, entraid *config.EntraIDConfig, requestInfo entraIDRequestInfo) oidcEndpointSet {
	return oidcEndpointsForRequest(issuer, entraid, discoveryRequestInfo(entraid, requestInfo))
}

func publicIssuerForRequest(r *http.Request, configuredIssuer string) string {
	configuredIssuer = strings.TrimSpace(configuredIssuer)
	if r == nil {
		return configuredIssuer
	}

	scheme := "http"
	if forwardedProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwardedProto != "" {
		scheme = strings.ToLower(strings.TrimSpace(strings.Split(forwardedProto, ",")[0]))
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := strings.TrimSpace(r.Host)
	if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		host = strings.TrimSpace(strings.Split(forwardedHost, ",")[0])
	}
	if host == "" {
		return configuredIssuer
	}

	return scheme + "://" + host + config.IssuerPathPrefix(configuredIssuer)
}

func startupDisplayFromEndpoints(endpoints oidcEndpointSet, tenants []string) entraIDStartupDisplay {
	return entraIDStartupDisplay{
		Discovery:           endpoints.Discovery,
		Authorize:           endpoints.Authorize,
		Token:               endpoints.Token,
		UserInfo:            endpoints.UserInfo,
		Introspection:       endpoints.Introspection,
		Revocation:          endpoints.Revocation,
		Logout:              endpoints.Logout,
		DeviceAuthorization: endpoints.DeviceAuthorization,
		JWKS:                endpoints.JWKS,
		HealthCheck:         endpoints.HealthCheck,
		Tenants:             tenants,
	}
}
