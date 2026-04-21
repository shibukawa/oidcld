package config

import (
	"errors"
	"fmt"
	neturl "net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

const DefaultReverseProxyLogRetention = 200

var DefaultReverseProxyIgnoreLogPaths = []string{"/health"}

var (
	ErrReverseProxyMixedListenerSchemes        = errors.New("reverse_proxy.hosts[] must use a single scheme when split listener mode is enabled")
	ErrReverseProxySplitPortRequiresHosts      = errors.New("--proxy-port requires at least one reverse_proxy host")
	ErrReverseProxySplitHostPortMismatch       = errors.New("reverse_proxy.hosts[].host explicit port must match --proxy-port in split listener mode")
	ErrReverseProxySplitSchemeCannotBeInferred = errors.New("reverse proxy listener scheme cannot be inferred from a default virtual host alone")
)

type ReverseProxyConfig struct {
	Hosts          []ReverseProxyHost `yaml:"hosts,omitempty"`
	LogRetention   int                `yaml:"log_retention,omitempty"`
	IgnoreLogPaths []string           `yaml:"ignore_log_paths,omitempty"`
}

type ReverseProxyHost struct {
	Host        string              `yaml:"host,omitempty"`
	TLSCertFile string              `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string              `yaml:"tls_key_file,omitempty"`
	CORS        *CORSConfig         `yaml:"cors,omitempty"`
	Routes      []ReverseProxyRoute `yaml:"routes,omitempty"`

	resolvedTLSCertFile string `yaml:"-"`
	resolvedTLSKeyFile  string `yaml:"-"`
	normalizedHost      string `yaml:"-"`
	normalizedScheme    string `yaml:"-"`
	normalizedHostname  string `yaml:"-"`
	normalizedPort      string `yaml:"-"`
	defaultVirtualHost  bool   `yaml:"-"`
}

type ReverseProxyRoute struct {
	Path              string                   `yaml:"path,omitempty"`
	Label             string                   `yaml:"label,omitempty"`
	TargetURL         string                   `yaml:"target_url,omitempty"`
	StaticDir         string                   `yaml:"static_dir,omitempty"`
	OpenAPIFile       string                   `yaml:"openapi_file,omitempty"`
	SPAFallback       bool                     `yaml:"spa_fallback,omitempty"`
	RewritePathPrefix string                   `yaml:"rewrite_path_prefix,omitempty"`
	Gateway           *ReverseProxyGateway     `yaml:"gateway,omitempty"`
	Mock              *ReverseProxyMockOptions `yaml:"mock,omitempty"`

	resolvedStaticDir   string `yaml:"-"`
	resolvedOpenAPIFile string `yaml:"-"`
	resolvedLabel       string `yaml:"-"`
}

type ReverseProxyGateway struct {
	Required               ReverseProxyGatewayRequired `yaml:"required,omitempty"`
	RequiredScopes         []string                    `yaml:"required_scopes,omitempty"`
	RequiredAudiences      []string                    `yaml:"required_audiences,omitempty"`
	ForwardClaimsAsHeaders map[string]string           `yaml:"forward_claims_as_headers,omitempty"`
	ReplayAuthorization    *bool                       `yaml:"replay_authorization,omitempty"`
}

type ReverseProxyGatewayRequired struct {
	Enabled bool           `yaml:"-"`
	Claims  map[string]any `yaml:"-"`
}

func (r *ReverseProxyGatewayRequired) UnmarshalYAML(b []byte) error {
	if r == nil {
		return nil
	}

	var enabled bool
	if err := yaml.Unmarshal(b, &enabled); err == nil {
		r.Enabled = enabled
		r.Claims = nil
		return nil
	}

	var claims map[string]any
	if err := yaml.Unmarshal(b, &claims); err != nil {
		return err
	}

	r.Enabled = true
	r.Claims = claims
	return nil
}

type ReverseProxyMockOptions struct {
	PreferExamples      bool   `yaml:"prefer_examples,omitempty"`
	DefaultStatus       string `yaml:"default_status,omitempty"`
	FallbackContentType string `yaml:"fallback_content_type,omitempty"`
}

func (c *Config) ReverseProxyUsesHTTPS() bool {
	if c == nil || c.ReverseProxy == nil {
		return false
	}
	for _, host := range c.ReverseProxy.Hosts {
		if host.IsDefaultVirtualHost() {
			return strings.HasPrefix(strings.TrimSpace(c.OIDC.Issuer), "https://")
		}
		if host.Scheme() == "https" {
			return true
		}
	}
	return false
}

func (c *Config) ReverseProxyListenerScheme() (string, error) {
	if c == nil || c.ReverseProxy == nil || len(c.ReverseProxy.Hosts) == 0 {
		return "", nil
	}

	resolvedScheme := ""
	hasExplicitHost := false
	for _, host := range c.ReverseProxy.Hosts {
		if host.IsDefaultVirtualHost() {
			continue
		}
		hasExplicitHost = true
		scheme := strings.ToLower(strings.TrimSpace(host.Scheme()))
		if scheme == "" {
			continue
		}
		if resolvedScheme == "" {
			resolvedScheme = scheme
			continue
		}
		if resolvedScheme != scheme {
			return "", ErrReverseProxyMixedListenerSchemes
		}
	}

	if resolvedScheme != "" {
		return resolvedScheme, nil
	}
	if hasExplicitHost {
		return "", nil
	}

	issuerScheme, _, _, ok := IssuerURLParts(c.OIDC.Issuer)
	if ok && issuerScheme != "" {
		return strings.ToLower(issuerScheme), nil
	}
	return "", ErrReverseProxySplitSchemeCannotBeInferred
}

func (c *Config) ValidateSplitListenerPorts(oidcPort, proxyPort, consolePort string) error {
	oidcPort = strings.TrimSpace(oidcPort)
	proxyPort = strings.TrimSpace(proxyPort)
	consolePort = strings.TrimSpace(consolePort)

	if proxyPort == "" {
		return nil
	}
	if c == nil || c.ReverseProxy == nil || len(c.ReverseProxy.Hosts) == 0 {
		return ErrReverseProxySplitPortRequiresHosts
	}
	if oidcPort != "" && oidcPort == proxyPort {
		return fmt.Errorf("oidc listener port %q conflicts with --proxy-port", proxyPort)
	}
	if consolePort != "" && consolePort == proxyPort {
		return fmt.Errorf("console port %q conflicts with --proxy-port", proxyPort)
	}

	if _, err := c.ReverseProxyListenerScheme(); err != nil {
		return err
	}
	for _, host := range c.ReverseProxy.Hosts {
		if host.IsDefaultVirtualHost() {
			continue
		}
		if host.Port() != "" && host.Port() != proxyPort {
			return fmt.Errorf("%w: %q", ErrReverseProxySplitHostPortMismatch, host.DisplayHost())
		}
	}
	return nil
}

func normalizeReverseProxyConfig(cfg *ReverseProxyConfig, sourceDir string) (*ReverseProxyConfig, error) {
	if cfg == nil {
		//nolint:nilnil // nil reverse_proxy means the feature is disabled.
		return nil, nil
	}

	normalized := &ReverseProxyConfig{
		LogRetention:   DefaultReverseProxyLogRetention,
		IgnoreLogPaths: append([]string(nil), DefaultReverseProxyIgnoreLogPaths...),
	}
	if cfg.LogRetention > 0 {
		normalized.LogRetention = cfg.LogRetention
	}
	if len(cfg.IgnoreLogPaths) > 0 {
		normalized.IgnoreLogPaths = make([]string, 0, len(cfg.IgnoreLogPaths))
		for _, pattern := range cfg.IgnoreLogPaths {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			normalized.IgnoreLogPaths = append(normalized.IgnoreLogPaths, pattern)
		}
		if len(normalized.IgnoreLogPaths) == 0 {
			normalized.IgnoreLogPaths = append([]string(nil), DefaultReverseProxyIgnoreLogPaths...)
		}
	}

	seenHosts := map[string]struct{}{}
	defaultHostCount := 0
	for _, host := range cfg.Hosts {
		normalizedHost, err := normalizeReverseProxyHost(host, sourceDir)
		if err != nil {
			return nil, err
		}
		if normalizedHost.IsDefaultVirtualHost() {
			defaultHostCount++
			if defaultHostCount > 1 {
				return nil, ErrReverseProxyMultipleDefaultHosts
			}
		} else {
			hostKey := strings.ToLower(normalizedHost.NormalizedHost())
			if _, exists := seenHosts[hostKey]; exists {
				return nil, fmt.Errorf("%w: %q", ErrReverseProxyDuplicateHost, normalizedHost.NormalizedHost())
			}
			seenHosts[hostKey] = struct{}{}
		}
		normalized.Hosts = append(normalized.Hosts, normalizedHost)
	}

	return normalized, nil
}

func normalizeReverseProxyHost(host ReverseProxyHost, sourceDir string) (ReverseProxyHost, error) {
	host.Host = strings.TrimSpace(host.Host)
	host.TLSCertFile = strings.TrimSpace(host.TLSCertFile)
	host.TLSKeyFile = strings.TrimSpace(host.TLSKeyFile)
	if len(host.Routes) == 0 {
		return ReverseProxyHost{}, ErrReverseProxyRouteRequired
	}
	if (host.TLSCertFile == "") != (host.TLSKeyFile == "") {
		return ReverseProxyHost{}, ErrReverseProxyTLSCertificateKeyRequired
	}

	host.CORS = normalizeCORSConfig(host.CORS)

	if host.Host == "" {
		host.defaultVirtualHost = true
	} else {
		normalizedHost, scheme, hostname, port, err := normalizeReverseProxyHostAuthority(host.Host)
		if err != nil {
			return ReverseProxyHost{}, err
		}
		host.Host = normalizedHost
		host.normalizedHost = normalizedHost
		host.normalizedScheme = scheme
		host.normalizedHostname = hostname
		host.normalizedPort = port
	}
	if host.TLSCertFile != "" {
		if host.Scheme() != "https" {
			return ReverseProxyHost{}, fmt.Errorf("%w: %q", ErrReverseProxyTLSRequiresHTTPSHost, host.Host)
		}
		resolvedCert, err := resolveConfigRelativePath(sourceDir, host.TLSCertFile)
		if err != nil {
			return ReverseProxyHost{}, fmt.Errorf("failed to resolve reverse_proxy.hosts[%s].tls_cert_file: %w", host.Host, err)
		}
		resolvedKey, err := resolveConfigRelativePath(sourceDir, host.TLSKeyFile)
		if err != nil {
			return ReverseProxyHost{}, fmt.Errorf("failed to resolve reverse_proxy.hosts[%s].tls_key_file: %w", host.Host, err)
		}
		host.resolvedTLSCertFile = resolvedCert
		host.resolvedTLSKeyFile = resolvedKey
	}

	normalizedRoutes := make([]ReverseProxyRoute, 0, len(host.Routes))
	for _, route := range host.Routes {
		normalizedRoute, err := normalizeReverseProxyRoute(route, sourceDir)
		if err != nil {
			return ReverseProxyHost{}, fmt.Errorf("host %q: %w", host.DisplayHost(), err)
		}
		normalizedRoutes = append(normalizedRoutes, normalizedRoute)
	}
	slices.SortStableFunc(normalizedRoutes, func(a, b ReverseProxyRoute) int {
		return len(b.Path) - len(a.Path)
	})
	host.Routes = normalizedRoutes

	return host, nil
}

func normalizeReverseProxyHostAuthority(value string) (normalizedHost string, scheme string, hostname string, port string, err error) {
	parsed, err := neturl.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", "", "", "", ErrReverseProxyHostAuthorityInvalid
	}
	scheme = strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", "", "", "", ErrReverseProxyHostSchemeInvalid
	}
	if parsed.Host == "" || parsed.Opaque != "" {
		return "", "", "", "", ErrReverseProxyHostNameRequired
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", "", "", ErrReverseProxyHostExtraComponents
	}

	hostname = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	port = strings.TrimSpace(parsed.Port())
	if hostname == "" {
		return "", "", "", "", ErrReverseProxyHostNameRequired
	}

	normalizedHost = scheme + "://" + hostname
	if port != "" {
		normalizedHost += ":" + port
	}
	return normalizedHost, scheme, hostname, port, nil
}

func normalizeReverseProxyRoute(route ReverseProxyRoute, sourceDir string) (ReverseProxyRoute, error) {
	route.Path = strings.TrimSpace(route.Path)
	route.Label = strings.TrimSpace(route.Label)
	route.TargetURL = strings.TrimSpace(route.TargetURL)
	route.StaticDir = strings.TrimSpace(route.StaticDir)
	route.OpenAPIFile = strings.TrimSpace(route.OpenAPIFile)
	route.RewritePathPrefix = strings.TrimSpace(route.RewritePathPrefix)

	if route.Path == "" {
		route.Path = "/"
	}
	if !strings.HasPrefix(route.Path, "/") {
		return ReverseProxyRoute{}, ErrReverseProxyRoutePathInvalid
	}
	if route.RewritePathPrefix != "" && !strings.HasPrefix(route.RewritePathPrefix, "/") {
		return ReverseProxyRoute{}, ErrReverseProxyRewritePathPrefixInvalid
	}

	targetCount := 0
	if route.TargetURL != "" {
		targetCount++
		parsed, err := neturl.Parse(route.TargetURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return ReverseProxyRoute{}, ErrReverseProxyRouteTargetInvalid
		}
		if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
			return ReverseProxyRoute{}, ErrReverseProxyRouteTargetInvalid
		}
	}
	if route.StaticDir != "" {
		targetCount++
		resolved, err := resolveConfigRelativePath(sourceDir, route.StaticDir)
		if err != nil {
			return ReverseProxyRoute{}, fmt.Errorf("failed to resolve reverse_proxy.hosts[].routes[].static_dir: %w", err)
		}
		route.resolvedStaticDir = filepath.Clean(resolved)
	}
	if route.OpenAPIFile != "" {
		targetCount++
		resolved, err := resolveConfigRelativePath(sourceDir, route.OpenAPIFile)
		if err != nil {
			return ReverseProxyRoute{}, fmt.Errorf("failed to resolve reverse_proxy.hosts[].routes[].openapi_file: %w", err)
		}
		route.resolvedOpenAPIFile = filepath.Clean(resolved)
	}
	if targetCount != 1 {
		return ReverseProxyRoute{}, ErrReverseProxyRouteTargetRequired
	}
	if route.SPAFallback && route.StaticDir == "" {
		return ReverseProxyRoute{}, ErrReverseProxySPAFallbackRequiresStaticDir
	}
	if route.Gateway != nil && route.StaticDir != "" {
		return ReverseProxyRoute{}, ErrReverseProxyGatewayNotSupportedForStatic
	}
	if route.Gateway != nil {
		route.Gateway = normalizeReverseProxyGateway(route.Gateway)
	}
	if route.Mock != nil {
		route.Mock = normalizeReverseProxyMock(route.Mock)
	}
	route.resolvedLabel = deriveReverseProxyRouteLabel(route)

	return route, nil
}

func deriveReverseProxyRouteLabel(route ReverseProxyRoute) string {
	if route.Label != "" {
		return route.Label
	}
	if route.TargetURL != "" {
		if parsed, err := neturl.Parse(route.TargetURL); err == nil {
			hostname := strings.TrimSpace(parsed.Hostname())
			if hostname != "" {
				parts := strings.Split(hostname, ".")
				if len(parts) > 0 && parts[0] != "" {
					return parts[0]
				}
				return hostname
			}
		}
	}
	if route.StaticDir != "" {
		base := filepath.Base(route.StaticDir)
		if base != "." && base != string(filepath.Separator) && base != "" {
			return base
		}
	}
	if route.OpenAPIFile != "" {
		base := filepath.Base(route.OpenAPIFile)
		if base != "." && base != string(filepath.Separator) && base != "" {
			return strings.TrimSuffix(base, filepath.Ext(base))
		}
	}
	if route.Path == "/" {
		return "root"
	}
	return strings.TrimPrefix(route.Path, "/")
}

func normalizeReverseProxyGateway(gateway *ReverseProxyGateway) *ReverseProxyGateway {
	if gateway == nil {
		return nil
	}
	normalized := &ReverseProxyGateway{
		Required: ReverseProxyGatewayRequired{
			Enabled: gateway.Required.Enabled,
			Claims:  map[string]any{},
		},
		RequiredScopes:         make([]string, 0, len(gateway.RequiredScopes)),
		RequiredAudiences:      make([]string, 0, len(gateway.RequiredAudiences)),
		ForwardClaimsAsHeaders: map[string]string{},
		ReplayAuthorization:    gateway.ReplayAuthorization,
	}
	for claim, value := range gateway.Required.Claims {
		claim = strings.TrimSpace(claim)
		if claim == "" {
			continue
		}
		if normalizedValue, ok := normalizeReverseProxyGatewayRequiredValue(value); ok {
			normalized.Required.Claims[claim] = normalizedValue
		}
	}
	for _, scope := range gateway.RequiredScopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			normalized.RequiredScopes = append(normalized.RequiredScopes, scope)
		}
	}
	for _, audience := range gateway.RequiredAudiences {
		audience = strings.TrimSpace(audience)
		if audience != "" {
			normalized.RequiredAudiences = append(normalized.RequiredAudiences, audience)
		}
	}
	for claim, header := range gateway.ForwardClaimsAsHeaders {
		claim = strings.TrimSpace(claim)
		header = strings.TrimSpace(header)
		if claim == "" || header == "" {
			continue
		}
		normalized.ForwardClaimsAsHeaders[claim] = header
	}
	if len(normalized.RequiredScopes) > 0 {
		normalized.Required.Enabled = true
		if _, exists := normalized.Required.Claims["scope"]; !exists {
			if len(normalized.RequiredScopes) == 1 {
				normalized.Required.Claims["scope"] = normalized.RequiredScopes[0]
			} else {
				normalized.Required.Claims["scope"] = append([]string(nil), normalized.RequiredScopes...)
			}
		}
	}
	if len(normalized.RequiredAudiences) > 0 {
		normalized.Required.Enabled = true
		if _, exists := normalized.Required.Claims["aud"]; !exists {
			if len(normalized.RequiredAudiences) == 1 {
				normalized.Required.Claims["aud"] = normalized.RequiredAudiences[0]
			} else {
				normalized.Required.Claims["aud"] = append([]string(nil), normalized.RequiredAudiences...)
			}
		}
	}
	if len(normalized.Required.Claims) > 0 {
		normalized.Required.Enabled = true
	}
	return normalized
}

func normalizeReverseProxyGatewayRequiredValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		typed = strings.TrimSpace(typed)
		return typed, typed != ""
	case []string:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
		if len(result) == 0 {
			return nil, false
		}
		return result, true
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				result = append(result, text)
			}
		}
		if len(result) == 0 {
			return nil, false
		}
		return result, true
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "<nil>" {
			return nil, false
		}
		return text, true
	}
}

func normalizeReverseProxyMock(mock *ReverseProxyMockOptions) *ReverseProxyMockOptions {
	if mock == nil {
		return nil
	}
	return &ReverseProxyMockOptions{
		PreferExamples:      mock.PreferExamples,
		DefaultStatus:       strings.TrimSpace(mock.DefaultStatus),
		FallbackContentType: strings.TrimSpace(mock.FallbackContentType),
	}
}

func (h ReverseProxyHost) ResolvedTLSCertFile() string {
	if h.resolvedTLSCertFile != "" {
		return h.resolvedTLSCertFile
	}
	return h.TLSCertFile
}

func (h ReverseProxyHost) ResolvedTLSKeyFile() string {
	if h.resolvedTLSKeyFile != "" {
		return h.resolvedTLSKeyFile
	}
	return h.TLSKeyFile
}

func (h ReverseProxyHost) NormalizedHost() string {
	if h.defaultVirtualHost {
		return ""
	}
	if h.normalizedHost != "" {
		return h.normalizedHost
	}
	return strings.TrimSpace(h.Host)
}

func (h ReverseProxyHost) Scheme() string {
	if h.defaultVirtualHost {
		if h.TLSCertFile != "" || h.TLSKeyFile != "" {
			return "https"
		}
		return ""
	}
	if h.normalizedScheme != "" {
		return h.normalizedScheme
	}
	_, scheme, hostname, port, err := normalizeReverseProxyHostAuthority(h.Host)
	if err != nil {
		return ""
	}
	_ = hostname
	_ = port
	return scheme
}

func (h ReverseProxyHost) Hostname() string {
	if h.defaultVirtualHost {
		return ""
	}
	if h.normalizedHostname != "" {
		return h.normalizedHostname
	}
	normalizedHost, scheme, hostname, port, err := normalizeReverseProxyHostAuthority(h.Host)
	if err != nil {
		return ""
	}
	_ = normalizedHost
	_ = scheme
	_ = port
	return hostname
}

func (h ReverseProxyHost) Port() string {
	if h.defaultVirtualHost {
		return ""
	}
	if h.normalizedPort != "" {
		return h.normalizedPort
	}
	normalizedHost, scheme, hostname, port, err := normalizeReverseProxyHostAuthority(h.Host)
	if err != nil {
		return ""
	}
	_ = normalizedHost
	_ = scheme
	_ = hostname
	return port
}

func (r ReverseProxyRoute) ResolvedStaticDir() string {
	if r.resolvedStaticDir != "" {
		return r.resolvedStaticDir
	}
	return r.StaticDir
}

func (r ReverseProxyRoute) ResolvedOpenAPIFile() string {
	if r.resolvedOpenAPIFile != "" {
		return r.resolvedOpenAPIFile
	}
	return r.OpenAPIFile
}

func (r ReverseProxyRoute) ResolvedLabel() string {
	if r.resolvedLabel != "" {
		return r.resolvedLabel
	}
	return deriveReverseProxyRouteLabel(r)
}

func (h ReverseProxyHost) IsDefaultVirtualHost() bool {
	return h.defaultVirtualHost
}

func (h ReverseProxyHost) DisplayHost() string {
	if h.IsDefaultVirtualHost() {
		return "(default virtual host)"
	}
	return h.NormalizedHost()
}
