package server

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/shibukawa/oidcld/internal/config"
)

type entraIDRoutes struct {
	Authorize           string
	Token               string
	UserInfo            string
	Introspection       string
	Revocation          string
	Logout              string
	DeviceAuthorization string
	JWKS                string
}

type entraIDRequestInfo struct {
	Tenant     string
	Tenantless bool
}

func (s *Server) entraIDRouteMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, matched, err := matchEntraIDRoute(r.URL.Path, s.config.EntraID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if !matched {
			next.ServeHTTP(w, r)
			return
		}
		if route.RequestInfo.Tenantless {
			s.warnTenantlessEntraIDRequest(route, r)
		}

		rewritten := rewriteRequestPath(r, route.CanonicalPath)
		ctx := context.WithValue(rewritten.Context(), entraIDRequestInfoKey, route.RequestInfo)
		next.ServeHTTP(w, rewritten.WithContext(ctx))
	})
}

type entraIDRouteMatch struct {
	CanonicalPath string
	RequestInfo   entraIDRequestInfo
}

func matchEntraIDRoute(path string, entraid *config.EntraIDConfig) (entraIDRouteMatch, bool, error) {
	if entraid == nil {
		return entraIDRouteMatch{}, false, nil
	}

	segments := splitRequestPath(path)
	if len(segments) == 0 {
		return entraIDRouteMatch{}, false, nil
	}

	switch strings.ToLower(entraid.Version) {
	case "v1":
		return matchEntraIDV1Route(segments, entraid)
	case "v2":
		return matchEntraIDV2VersionedRoute(segments, entraid)
	default:
		return entraIDRouteMatch{}, false, nil
	}
}

func matchEntraIDV2VersionedRoute(segments []string, entraid *config.EntraIDConfig) (entraIDRouteMatch, bool, error) {
	if len(segments) == 3 && segments[0] == "v2.0" && segments[1] == ".well-known" && segments[2] == "openid-configuration" {
		return entraIDRouteMatch{CanonicalPath: "/.well-known/openid-configuration", RequestInfo: entraIDRequestInfo{Tenantless: true}}, true, nil
	}
	if len(segments) == 4 && segments[1] == "v2.0" && segments[2] == ".well-known" && segments[3] == "openid-configuration" {
		if err := validateEntraIDRequestTenant(segments[0], entraid); err != nil {
			return entraIDRouteMatch{}, true, err
		}
		return entraIDRouteMatch{CanonicalPath: "/.well-known/openid-configuration", RequestInfo: entraIDRequestInfo{Tenant: segments[0]}}, true, nil
	}
	if canonicalPath, ok := canonicalV2SharedEndpointPath(segments, false); ok {
		return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenantless: true}}, true, nil
	}
	if len(segments) >= 3 {
		if canonicalPath, ok := canonicalV2SharedEndpointPath(segments[1:], true); ok {
			if err := validateEntraIDRequestTenant(segments[0], entraid); err != nil {
				return entraIDRouteMatch{}, true, err
			}
			return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenant: segments[0]}}, true, nil
		}
	}

	if canonicalPath, ok := canonicalV2EndpointPath(segments, false); ok {
		return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenantless: true}}, true, nil
	}
	if len(segments) >= 4 {
		if canonicalPath, ok := canonicalV2EndpointPath(segments[1:], true); ok {
			if err := validateEntraIDRequestTenant(segments[0], entraid); err != nil {
				return entraIDRouteMatch{}, true, err
			}
			return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenant: segments[0]}}, true, nil
		}
	}

	return entraIDRouteMatch{}, false, nil
}

func matchEntraIDV1Route(segments []string, entraid *config.EntraIDConfig) (entraIDRouteMatch, bool, error) {
	if canonicalPath, ok := canonicalEntraRootPath(segments); ok {
		return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenantless: true}}, true, nil
	}
	if len(segments) == 3 && segments[1] == ".well-known" && segments[2] == "openid-configuration" {
		if err := validateEntraIDRequestTenant(segments[0], entraid); err != nil {
			return entraIDRouteMatch{}, true, err
		}
		return entraIDRouteMatch{CanonicalPath: "/.well-known/openid-configuration", RequestInfo: entraIDRequestInfo{Tenant: segments[0]}}, true, nil
	}

	if canonicalPath, ok := canonicalV1EndpointPath(segments, false); ok {
		return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenantless: true}}, true, nil
	}
	if len(segments) >= 3 {
		if canonicalPath, ok := canonicalV1EndpointPath(segments[1:], true); ok {
			if err := validateEntraIDRequestTenant(segments[0], entraid); err != nil {
				return entraIDRouteMatch{}, true, err
			}
			return entraIDRouteMatch{CanonicalPath: canonicalPath, RequestInfo: entraIDRequestInfo{Tenant: segments[0]}}, true, nil
		}
	}

	return entraIDRouteMatch{}, false, nil
}

func canonicalEntraRootPath(segments []string) (string, bool) {
	if len(segments) == 2 && segments[0] == ".well-known" && segments[1] == "openid-configuration" {
		return "/.well-known/openid-configuration", true
	}
	if len(segments) != 1 {
		return "", false
	}
	return canonicalEntraCorePath(segments[0])
}

func canonicalV2SharedEndpointPath(segments []string, tenantScoped bool) (string, bool) {
	if len(segments) >= 1 && segments[0] != "v2.0" {
		return "", false
	}
	if len(segments) == 2 && segments[0] == "v2.0" {
		switch segments[1] {
		case "userinfo":
			return "/userinfo", true
		case "revoke":
			return "/revoke", true
		case "health":
			return "/health", true
		}
	}
	if len(segments) == 3 && segments[0] == "v2.0" && segments[1] == "oauth" && segments[2] == "introspect" {
		return "/oauth/introspect", true
	}
	if tenantScoped {
		return "", false
	}
	return "", false
}

func canonicalEntraCorePath(segment string) (string, bool) {
	switch segment {
	case "authorize":
		return "/authorize", true
	case "token":
		return "/token", true
	case "end_session":
		return "/end_session", true
	case "device_authorization":
		return "/device_authorization", true
	case "keys":
		return "/keys", true
	default:
		return "", false
	}
}

func canonicalV1EndpointPath(segments []string, tenantScoped bool) (string, bool) {
	if len(segments) == 2 && segments[0] == "oauth2" {
		switch segments[1] {
		case "authorize":
			return "/authorize", true
		case "token":
			return "/token", true
		case "logout":
			return "/end_session", true
		case "devicecode":
			return "/device_authorization", true
		}
	}
	if len(segments) == 2 && segments[0] == "discovery" && segments[1] == "keys" {
		return "/keys", true
	}
	if tenantScoped {
		return "", false
	}
	return "", false
}

func splitRequestPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func canonicalV2EndpointPath(segments []string, tenantScoped bool) (string, bool) {
	if len(segments) == 3 && segments[0] == "oauth2" && segments[1] == "v2.0" {
		switch segments[2] {
		case "authorize":
			return "/authorize", true
		case "token":
			return "/token", true
		case "logout":
			return "/end_session", true
		case "devicecode":
			return "/device_authorization", true
		}
	}
	if len(segments) == 3 && segments[0] == "discovery" && segments[1] == "v2.0" && segments[2] == "keys" {
		return "/keys", true
	}
	if tenantScoped {
		return "", false
	}
	return "", false
}

func validateEntraIDRequestTenant(requestedTenant string, entraid *config.EntraIDConfig) error {
	requestedTenant = strings.Trim(requestedTenant, "/")
	if requestedTenant == "" {
		return nil
	}
	if entraid == nil {
		return fmt.Errorf("tenant %q: %w", requestedTenant, ErrEntraIDTenantRequiresConfiguration)
	}

	configuredTenant := strings.Trim(entraid.TenantID, "/")
	if strings.EqualFold(requestedTenant, configuredTenant) {
		return nil
	}
	if isAllowedEntraIDTenantAlias(requestedTenant) {
		return nil
	}
	if isGUIDTenant(requestedTenant) {
		return fmt.Errorf("tenant %q: %w", requestedTenant, ErrEntraIDTenantIDMismatch)
	}
	return fmt.Errorf("tenant %q: %w", requestedTenant, ErrEntraIDTenantNotAllowed)
}

func allowedEntraIDTenantValues(entraid *config.EntraIDConfig) []string {
	values := []string{"common", "organizations", "customers", "contoso.onmicrosoft.com"}
	if entraid == nil {
		return values
	}
	configuredTenant := strings.Trim(entraid.TenantID, "/")
	if configuredTenant != "" && !slices.Contains(values, configuredTenant) {
		values = append(values, configuredTenant)
	}
	return values
}

func (s *Server) warnTenantlessEntraIDRequest(route entraIDRouteMatch, r *http.Request) {
	version := "unknown"
	if s != nil && s.config != nil && s.config.EntraID != nil {
		version = s.config.EntraID.Version
	}
	path := route.CanonicalPath
	if r != nil && r.URL != nil && r.URL.Path != "" {
		path = r.URL.Path
	}
	message := fmt.Sprintf("tenantless EntraID %s request accepted for %s", version, path)
	if s != nil && s.prettyLog != nil {
		s.prettyLog.Warning(message)
		return
	}
	if s != nil && s.logger != nil {
		s.logger.Warn(message)
	}
}

type entraIDStartupDisplay struct {
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
	Tenants             []string
}

func entraIDStartupDisplayForIssuer(issuer string, entraid *config.EntraIDConfig) (entraIDStartupDisplay, bool) {
	if entraid == nil {
		return entraIDStartupDisplay{}, false
	}
	parsed, err := neturl.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return entraIDStartupDisplay{}, false
	}
	base := parsed.Scheme + "://" + parsed.Host
	placeholder := "{tenant}"
	display := entraIDStartupDisplay{Tenants: allowedEntraIDTenantValues(entraid)}

	switch strings.ToLower(entraid.Version) {
	case "v1":
		display.Discovery = base + "/" + placeholder + "/.well-known/openid-configuration"
		display.Authorize = base + "/" + placeholder + "/oauth2/authorize"
		display.Token = base + "/" + placeholder + "/oauth2/token"
		display.UserInfo = base + "/" + placeholder + "/userinfo"
		display.Introspection = base + "/" + placeholder + "/oauth/introspect"
		display.Revocation = base + "/" + placeholder + "/revoke"
		display.Logout = base + "/" + placeholder + "/oauth2/logout"
		display.DeviceAuthorization = base + "/" + placeholder + "/oauth2/devicecode"
		display.JWKS = base + "/" + placeholder + "/discovery/keys"
		display.HealthCheck = base + "/" + placeholder + "/health"
		return display, true
	case "v2":
		display.Discovery = base + "/" + placeholder + "/v2.0/.well-known/openid-configuration"
		display.Authorize = base + "/" + placeholder + "/oauth2/v2.0/authorize"
		display.Token = base + "/" + placeholder + "/oauth2/v2.0/token"
		display.UserInfo = base + "/" + placeholder + "/v2.0/userinfo"
		display.Introspection = base + "/" + placeholder + "/v2.0/oauth/introspect"
		display.Revocation = base + "/" + placeholder + "/v2.0/revoke"
		display.Logout = base + "/" + placeholder + "/oauth2/v2.0/logout"
		display.DeviceAuthorization = base + "/" + placeholder + "/oauth2/v2.0/devicecode"
		display.JWKS = base + "/" + placeholder + "/discovery/v2.0/keys"
		display.HealthCheck = base + "/" + placeholder + "/v2.0/health"
		return display, true
	default:
		return entraIDStartupDisplay{}, false
	}
}

func isAllowedEntraIDTenantAlias(tenant string) bool {
	switch strings.ToLower(tenant) {
	case "common", "organizations", "customers", "contoso.onmicrosoft.com":
		return true
	default:
		return false
	}
}

func isGUIDTenant(tenant string) bool {
	_, err := uuid.Parse(tenant)
	return err == nil
}

func entraIDRequestInfoFromRequest(r *http.Request) entraIDRequestInfo {
	if r == nil {
		return entraIDRequestInfo{}
	}
	info, ok := r.Context().Value(entraIDRequestInfoKey).(entraIDRequestInfo)
	if !ok {
		return entraIDRequestInfo{}
	}
	return info
}

func entraIDRoutesForRequest(issuer string, entraid *config.EntraIDConfig, requestInfo entraIDRequestInfo) (entraIDRoutes, bool) {
	if entraid == nil {
		return entraIDRoutes{}, false
	}

	parsed, err := neturl.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return entraIDRoutes{}, false
	}

	base := parsed.Scheme + "://" + parsed.Host
	tenantID := strings.Trim(entraid.TenantID, "/")
	if requestInfo.Tenantless {
		tenantID = ""
	}
	if requestInfo.Tenant != "" {
		tenantID = strings.Trim(requestInfo.Tenant, "/")
	}
	if tenantID == "" && !requestInfo.Tenantless {
		return entraIDRoutes{}, false
	}

	switch strings.ToLower(entraid.Version) {
	case "v1":
		prefix := base
		if tenantID != "" {
			prefix += "/" + tenantID
		}
		return entraIDRoutes{
			Authorize:           prefix + "/oauth2/authorize",
			Token:               prefix + "/oauth2/token",
			UserInfo:            prefix + "/userinfo",
			Introspection:       prefix + "/oauth/introspect",
			Revocation:          prefix + "/revoke",
			Logout:              prefix + "/oauth2/logout",
			DeviceAuthorization: prefix + "/oauth2/devicecode",
			JWKS:                prefix + "/discovery/keys",
		}, true
	case "v2":
		prefix := base
		if tenantID != "" {
			prefix += "/" + tenantID
		}
		return entraIDRoutes{
			Authorize:           prefix + "/oauth2/v2.0/authorize",
			Token:               prefix + "/oauth2/v2.0/token",
			UserInfo:            prefix + "/v2.0/userinfo",
			Introspection:       prefix + "/v2.0/oauth/introspect",
			Revocation:          prefix + "/v2.0/revoke",
			Logout:              prefix + "/oauth2/v2.0/logout",
			DeviceAuthorization: prefix + "/oauth2/v2.0/devicecode",
			JWKS:                prefix + "/discovery/v2.0/keys",
		}, true
	default:
		return entraIDRoutes{}, false
	}
}
