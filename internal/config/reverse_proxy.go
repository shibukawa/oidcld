package config

import (
	"fmt"
	neturl "net/url"
	"path/filepath"
	"slices"
	"strings"
)

const DefaultReverseProxyLogRetention = 200

type ReverseProxyConfig struct {
	Hosts        []ReverseProxyHost `yaml:"hosts,omitempty"`
	LogRetention int                `yaml:"log_retention,omitempty"`
}

type ReverseProxyHost struct {
	Host        string              `yaml:"host,omitempty"`
	HTTPS       bool                `yaml:"https,omitempty"`
	TLSCertFile string              `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string              `yaml:"tls_key_file,omitempty"`
	Routes      []ReverseProxyRoute `yaml:"routes,omitempty"`

	resolvedTLSCertFile string `yaml:"-"`
	resolvedTLSKeyFile  string `yaml:"-"`
}

type ReverseProxyRoute struct {
	Path              string `yaml:"path,omitempty"`
	TargetURL         string `yaml:"target_url,omitempty"`
	StaticDir         string `yaml:"static_dir,omitempty"`
	SPAFallback       bool   `yaml:"spa_fallback,omitempty"`
	RewritePathPrefix string `yaml:"rewrite_path_prefix,omitempty"`

	resolvedStaticDir string `yaml:"-"`
}

func (c *Config) ReverseProxyUsesHTTPS() bool {
	if c == nil || c.ReverseProxy == nil {
		return false
	}
	for _, host := range c.ReverseProxy.Hosts {
		if host.HTTPS {
			return true
		}
	}
	return false
}

func normalizeReverseProxyConfig(cfg *ReverseProxyConfig, sourceDir string) (*ReverseProxyConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	normalized := &ReverseProxyConfig{
		LogRetention: DefaultReverseProxyLogRetention,
	}
	if cfg.LogRetention > 0 {
		normalized.LogRetention = cfg.LogRetention
	}

	seenHosts := map[string]struct{}{}
	for _, host := range cfg.Hosts {
		normalizedHost, err := normalizeReverseProxyHost(host, sourceDir)
		if err != nil {
			return nil, err
		}
		hostKey := strings.ToLower(normalizedHost.Host)
		if _, exists := seenHosts[hostKey]; exists {
			return nil, fmt.Errorf("duplicate reverse_proxy host %q", normalizedHost.Host)
		}
		seenHosts[hostKey] = struct{}{}
		normalized.Hosts = append(normalized.Hosts, normalizedHost)
	}

	return normalized, nil
}

func normalizeReverseProxyHost(host ReverseProxyHost, sourceDir string) (ReverseProxyHost, error) {
	host.Host = strings.TrimSpace(host.Host)
	host.TLSCertFile = strings.TrimSpace(host.TLSCertFile)
	host.TLSKeyFile = strings.TrimSpace(host.TLSKeyFile)
	if host.Host == "" {
		return ReverseProxyHost{}, ErrReverseProxyHostRequired
	}
	if len(host.Routes) == 0 {
		return ReverseProxyHost{}, ErrReverseProxyRouteRequired
	}
	if (host.TLSCertFile == "") != (host.TLSKeyFile == "") {
		return ReverseProxyHost{}, ErrReverseProxyTLSCertificateKeyRequired
	}
	if host.TLSCertFile != "" {
		host.HTTPS = true
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
			return ReverseProxyHost{}, fmt.Errorf("host %q: %w", host.Host, err)
		}
		normalizedRoutes = append(normalizedRoutes, normalizedRoute)
	}
	slices.SortStableFunc(normalizedRoutes, func(a, b ReverseProxyRoute) int {
		return len(b.Path) - len(a.Path)
	})
	host.Routes = normalizedRoutes

	return host, nil
}

func normalizeReverseProxyRoute(route ReverseProxyRoute, sourceDir string) (ReverseProxyRoute, error) {
	route.Path = strings.TrimSpace(route.Path)
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
		return ReverseProxyRoute{}, fmt.Errorf("reverse_proxy.hosts[].routes[].rewrite_path_prefix must start with /")
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

	return route, nil
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

func (r ReverseProxyRoute) ResolvedStaticDir() string {
	if r.resolvedStaticDir != "" {
		return r.resolvedStaticDir
	}
	return r.StaticDir
}
