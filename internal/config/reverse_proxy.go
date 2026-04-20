package config

import (
	"fmt"
	neturl "net/url"
	"path/filepath"
	"slices"
	"strings"
)

const DefaultReverseProxyLogRetention = 200

var DefaultReverseProxyIgnoreLogPaths = []string{"/health"}

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
	Path              string `yaml:"path,omitempty"`
	Label             string `yaml:"label,omitempty"`
	TargetURL         string `yaml:"target_url,omitempty"`
	StaticDir         string `yaml:"static_dir,omitempty"`
	SPAFallback       bool   `yaml:"spa_fallback,omitempty"`
	RewritePathPrefix string `yaml:"rewrite_path_prefix,omitempty"`

	resolvedStaticDir string `yaml:"-"`
	resolvedLabel     string `yaml:"-"`
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
	if targetCount != 1 {
		return ReverseProxyRoute{}, ErrReverseProxyRouteTargetRequired
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
	if route.Path == "/" {
		return "root"
	}
	return strings.TrimPrefix(route.Path, "/")
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

func (r ReverseProxyRoute) ResolvedLabel() string {
	if r.resolvedLabel != "" {
		return r.resolvedLabel
	}
	return r.Label
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
