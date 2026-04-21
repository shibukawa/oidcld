package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

var ErrReverseProxyHTTPSRequiresCertificateAuthority = errors.New("reverse proxy https hosts require certificate_authority or manual host certificates")
var ErrReverseProxyHostNotCoveredByCADomains = errors.New("reverse proxy host is not covered by certificate_authority.domains")

type compiledReverseProxy struct {
	hosts       map[string][]*compiledReverseProxyHost
	defaultHost *compiledReverseProxyHost
}

type compiledReverseProxyHost struct {
	host          string
	scheme        string
	hostname      string
	port          string
	displayHost   string
	cors          *config.CORSConfig
	isDefaultHost bool
	routes        []compiledReverseProxyRoute
	manualTLSCert *tls.Certificate
}

type compiledReverseProxyRoute struct {
	path              string
	targetURL         *neturl.URL
	staticDir         string
	openapiFile       string
	spaFallback       bool
	rewritePathPrefix string
	targetLabel       string
	label             string
	routeType         string
	proxy             *httputil.ReverseProxy
	mock              *compiledOpenAPIMockRoute
	gateway           *compiledReverseProxyGateway
}

type reverseProxyRouteMatch struct {
	host  *compiledReverseProxyHost
	route compiledReverseProxyRoute
}

type reverseProxyRequestAuthority struct {
	scheme   string
	hostname string
	port     string
}

func newCompiledReverseProxy(cfg *config.Config) (*compiledReverseProxy, error) {
	if cfg == nil || cfg.ReverseProxy == nil || len(cfg.ReverseProxy.Hosts) == 0 {
		//nolint:nilnil // nil reverse proxy means no reverse proxy routes are configured.
		return nil, nil
	}

	compiled := &compiledReverseProxy{hosts: map[string][]*compiledReverseProxyHost{}}
	for _, host := range cfg.ReverseProxy.Hosts {
		item := &compiledReverseProxyHost{
			host:          host.NormalizedHost(),
			scheme:        host.Scheme(),
			hostname:      host.Hostname(),
			port:          host.Port(),
			displayHost:   host.DisplayHost(),
			cors:          host.CORS,
			isDefaultHost: host.IsDefaultVirtualHost(),
			routes:        make([]compiledReverseProxyRoute, 0, len(host.Routes)),
		}

		if host.ResolvedTLSCertFile() != "" {
			if item.hostname != "" {
				if err := validateHostMatchesCertificate(item.hostname, host.ResolvedTLSCertFile()); err != nil {
					return nil, err
				}
			}
			cert, err := tls.LoadX509KeyPair(host.ResolvedTLSCertFile(), host.ResolvedTLSKeyFile())
			if err != nil {
				return nil, err
			}
			item.manualTLSCert = &cert
		} else if host.Scheme() == "https" {
			if cfg.CertificateAuthority == nil {
				return nil, fmt.Errorf("%w: %s", ErrReverseProxyHTTPSRequiresCertificateAuthority, host.DisplayHost())
			}
			if item.hostname != "" && !config.HostMatchesCertificateDomains(item.hostname, cfg.CertificateAuthority.Domains) {
				return nil, fmt.Errorf("%w: %q", ErrReverseProxyHostNotCoveredByCADomains, host.DisplayHost())
			}
		}

		for _, route := range host.Routes {
			compiledRoute := compiledReverseProxyRoute{
				path:              route.Path,
				staticDir:         route.ResolvedStaticDir(),
				openapiFile:       route.ResolvedOpenAPIFile(),
				spaFallback:       route.SPAFallback,
				rewritePathPrefix: route.RewritePathPrefix,
				label:             route.ResolvedLabel(),
				gateway:           newCompiledReverseProxyGateway(route.Gateway),
			}
			if route.TargetURL != "" {
				targetURL, err := neturl.Parse(route.TargetURL)
				if err != nil {
					return nil, fmt.Errorf("invalid reverse proxy target %q: %w", route.TargetURL, err)
				}
				compiledRoute.targetURL = targetURL
				compiledRoute.routeType = "proxy"
				compiledRoute.targetLabel = route.TargetURL
				compiledRoute.proxy = newSingleHostReverseProxy(targetURL, route.Path, route.RewritePathPrefix)
			} else if route.OpenAPIFile != "" {
				mock, err := newCompiledOpenAPIMockRoute(route.ResolvedOpenAPIFile(), route.Mock)
				if err != nil {
					return nil, err
				}
				compiledRoute.routeType = "mock"
				compiledRoute.targetLabel = route.ResolvedOpenAPIFile()
				compiledRoute.mock = mock
			} else {
				compiledRoute.routeType = "static"
				compiledRoute.targetLabel = compiledRoute.staticDir
			}
			item.routes = append(item.routes, compiledRoute)
		}
		slices.SortStableFunc(item.routes, func(a, b compiledReverseProxyRoute) int {
			return len(b.path) - len(a.path)
		})
		if item.isDefaultHost {
			compiled.defaultHost = item
			continue
		}
		compiled.hosts[item.hostname] = append(compiled.hosts[item.hostname], item)
	}

	return compiled, nil
}

func reverseProxyLogRetention(cfg *config.Config) int {
	if cfg == nil || cfg.ReverseProxy == nil || cfg.ReverseProxy.LogRetention <= 0 {
		return config.DefaultReverseProxyLogRetention
	}
	return cfg.ReverseProxy.LogRetention
}

func newSingleHostReverseProxy(target *neturl.URL, matchPath, rewritePathPrefix string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	defaultDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalPath := req.URL.Path
		originalHost := req.Host
		defaultDirector(req)
		rewrittenPath := rewriteMatchedPath(originalPath, matchPath, rewritePathPrefix)
		req.URL.Path = singleJoiningSlash(target.Path, rewrittenPath)
		req.URL.RawPath = req.URL.EscapedPath()
		req.Host = target.Host
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", forwardedScheme(req))
	}
	return proxy
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

func forwardedScheme(req *http.Request) string {
	if req == nil {
		return "http"
	}
	if req.TLS != nil {
		return "https"
	}
	if req.Header.Get("X-Forwarded-Proto") != "" {
		return req.Header.Get("X-Forwarded-Proto")
	}
	return "http"
}

func rewriteMatchedPath(requestPath, matchPath, rewritePrefix string) string {
	if rewritePrefix == "" {
		return requestPath
	}
	trimmed := strings.TrimPrefix(requestPath, matchPath)
	if trimmed == "" {
		trimmed = "/"
	}
	return singleJoiningSlash(rewritePrefix, trimmed)
}

func (s *Server) reverseProxyMiddleware(next http.Handler) http.Handler {
	return s.reverseProxyMiddlewareWithOptions(next, true)
}

func (s *Server) reverseProxyOnlyMiddleware(next http.Handler) http.Handler {
	return s.reverseProxyMiddlewareWithOptions(next, false)
}

func (s *Server) reverseProxyMiddlewareWithOptions(next http.Handler, reserveOIDCPaths bool) http.Handler {
	if s == nil || s.reverseProxy == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reserveOIDCPaths && s.isReservedOIDCPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		match, ok := s.reverseProxy.match(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		s.serveMatchedReverseProxyRoute(w, r, match)
	})
}

func (s *Server) serveMatchedReverseProxyRoute(w http.ResponseWriter, r *http.Request, match reverseProxyRouteMatch) {
	if s == nil {
		http.NotFound(w, r)
		return
	}
	if !annotateAndAuthorizeReverseProxyRoute(s, w, r, match) {
		return
	}
	if match.route.routeType == "proxy" {
		s.maybeReplayReverseProxyAuthorization(r, match.route.gateway)
		match.route.proxy.ServeHTTP(w, r)
		return
	}
	if match.route.routeType == "mock" {
		s.serveOpenAPIMockRoute(w, r, match.route)
		return
	}
	s.serveStaticReverseProxyRoute(w, r, match.route)
}

func annotateAndAuthorizeReverseProxyRoute(s *Server, w http.ResponseWriter, r *http.Request, match reverseProxyRouteMatch) bool {
	if s == nil {
		return false
	}
	annotateReverseProxyLog(w, reverseProxyLogMeta{
		RouteType:         match.route.routeType,
		RouteHost:         match.host.displayHost,
		RoutePath:         match.route.path,
		RouteLabel:        match.route.label,
		Target:            match.route.targetLabel,
		RewritePathPrefix: match.route.rewritePathPrefix,
	})
	if handleCORS(w, r, match.host.cors) {
		return false
	}
	if !s.authorizeReverseProxyRoute(w, r, match.route.gateway) {
		return false
	}
	return true
}

func (c *compiledReverseProxy) match(r *http.Request) (reverseProxyRouteMatch, bool) {
	if c == nil || r == nil {
		return reverseProxyRouteMatch{}, false
	}
	requestAuthority := requestReverseProxyAuthority(r)
	if requestAuthority.hostname == "" || requestAuthority.scheme == "" {
		return reverseProxyRouteMatch{}, false
	}
	if candidates, ok := c.hosts[requestAuthority.hostname]; ok {
		for _, host := range candidates {
			if host.scheme != requestAuthority.scheme || host.port == "" || host.port != requestAuthority.port {
				continue
			}
			for _, route := range host.routes {
				if pathMatchesReverseProxyRoute(r.URL.Path, route.path) {
					return reverseProxyRouteMatch{host: host, route: route}, true
				}
			}
		}
		for _, host := range candidates {
			if host.scheme != requestAuthority.scheme || host.port != "" {
				continue
			}
			for _, route := range host.routes {
				if pathMatchesReverseProxyRoute(r.URL.Path, route.path) {
					return reverseProxyRouteMatch{host: host, route: route}, true
				}
			}
		}
	}
	if c.defaultHost != nil {
		for _, route := range c.defaultHost.routes {
			if pathMatchesReverseProxyRoute(r.URL.Path, route.path) {
				return reverseProxyRouteMatch{host: c.defaultHost, route: route}, true
			}
		}
	}
	return reverseProxyRouteMatch{}, false
}

func requestReverseProxyAuthority(r *http.Request) reverseProxyRequestAuthority {
	if r == nil {
		return reverseProxyRequestAuthority{}
	}
	host := strings.TrimSpace(r.Host)
	if host == "" && r.URL != nil {
		host = strings.TrimSpace(r.URL.Host)
	}
	if host == "" {
		return reverseProxyRequestAuthority{}
	}

	authority := reverseProxyRequestAuthority{
		scheme: "http",
	}
	if r.TLS != nil {
		authority.scheme = "https"
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		authority.hostname = strings.ToLower(strings.TrimSpace(parsedHost))
		authority.port = strings.TrimSpace(parsedPort)
		return authority
	}
	authority.hostname = strings.ToLower(strings.TrimSpace(host))
	return authority
}

func (c *compiledReverseProxy) tlsHost(hostname string) (*compiledReverseProxyHost, bool) {
	if c == nil {
		return nil, false
	}
	candidates, ok := c.hosts[strings.ToLower(strings.TrimSpace(hostname))]
	if ok {
		for _, host := range candidates {
			if host.scheme == "https" && host.manualTLSCert != nil {
				return host, true
			}
		}
		for _, host := range candidates {
			if host.scheme == "https" {
				return host, true
			}
		}
	}
	if c.defaultHost != nil {
		if c.defaultHost.manualTLSCert != nil {
			return c.defaultHost, true
		}
		return c.defaultHost, true
	}
	return nil, false
}

func pathMatchesReverseProxyRoute(requestPath, matchPath string) bool {
	if matchPath == "/" {
		return true
	}
	return requestPath == matchPath || strings.HasPrefix(requestPath, matchPath+"/")
}

func (s *Server) serveStaticReverseProxyRoute(w http.ResponseWriter, r *http.Request, route compiledReverseProxyRoute) {
	requestPath := rewriteMatchedPath(r.URL.Path, route.path, route.rewritePathPrefix)
	filePath := reverseProxyFilePath(route.staticDir, requestPath)
	info, err := os.Stat(filePath)
	if err == nil && info.IsDir() {
		filePath = filepath.Join(filePath, "index.html")
		info, err = os.Stat(filePath)
	}
	if err == nil && info.Mode().IsRegular() {
		http.ServeFile(w, r, filePath)
		return
	}
	if route.spaFallback {
		fallback := filepath.Join(route.staticDir, "index.html")
		if fallbackInfo, fallbackErr := os.Stat(fallback); fallbackErr == nil && fallbackInfo.Mode().IsRegular() {
			http.ServeFile(w, r, fallback)
			return
		}
	}
	http.NotFound(w, r)
}

func reverseProxyFilePath(root, requestPath string) string {
	cleanPath := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	relative := strings.TrimPrefix(cleanPath, "/")
	if relative == "" {
		relative = "index.html"
	}
	return filepath.Join(root, filepath.FromSlash(relative))
}

func (s *Server) isReservedOIDCPath(path string) bool {
	canonicalPath := s.canonicalOIDCPath(path)
	switch canonicalPath {
	case "/.well-known/openid-configuration", "/authorize", "/login", "/device", "/logged-out", "/logout/success", "/health", "/token", "/userinfo", "/keys":
		return true
	case "/oauth/introspect", "/oauth/revoke":
		return true
	}
	_, matched, err := matchEntraIDRoute(path, s.config.EntraID)
	return err == nil && matched
}

func (s *Server) canonicalOIDCPath(path string) string {
	prefix := config.IssuerPathPrefix(s.config.OIDC.Issuer)
	if prefix == "" {
		return path
	}
	switch {
	case path == prefix:
		return "/"
	case strings.HasPrefix(path, prefix+"/"):
		return strings.TrimPrefix(path, prefix)
	default:
		return path
	}
}

func annotateReverseProxyLog(w http.ResponseWriter, meta reverseProxyLogMeta) {
	if recorder, ok := w.(*responseWriter); ok {
		recorder.reverseProxy = &meta
	}
}

func (s *Server) oidcTrafficLogMeta(r *http.Request) *reverseProxyLogMeta {
	if s == nil || r == nil || r.URL == nil {
		return nil
	}

	canonicalPath := s.canonicalOIDCPath(r.URL.Path)
	if !s.isOIDCTrafficPath(canonicalPath, r.URL.Path) {
		return nil
	}

	return &reverseProxyLogMeta{
		RouteType:  "oidc",
		RouteHost:  strings.ToLower(strings.TrimSpace(config.IssuerHostname(s.config.OIDC.Issuer))),
		RoutePath:  canonicalPath,
		RouteLabel: "oidc",
		Target:     s.config.OIDC.Issuer,
	}
}

func (s *Server) isOIDCTrafficPath(canonicalPath, originalPath string) bool {
	switch canonicalPath {
	case "/.well-known/openid-configuration", "/authorize", "/login", "/device", "/logged-out", "/logout/success", "/health", "/token", "/userinfo", "/keys", "/oauth/introspect", "/oauth/revoke", "/end_session":
		return true
	}

	_, matched, err := matchEntraIDRoute(originalPath, s.config.EntraID)
	return err == nil && matched
}

func (s *Server) buildListenerTLSConfig(mainCertFile, mainKeyFile string) (*tls.Config, error) {
	var mainCert *tls.Certificate
	if mainCertFile != "" && mainKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(mainCertFile, mainKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate pair: %w", err)
		}
		mainCert = &cert
	}

	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(strings.TrimSpace(hello.ServerName))
			if host == "" {
				host = strings.ToLower(strings.TrimSpace(config.IssuerHostname(s.config.OIDC.Issuer)))
			}
			if s.reverseProxy != nil {
				if compiledHost, ok := s.reverseProxy.tlsHost(host); ok {
					if compiledHost.manualTLSCert != nil {
						return compiledHost.manualTLSCert, nil
					}
					leaf, err := s.ensureManagedLeafCertificateForHost(compiledHost.hostname)
					if err != nil {
						return nil, err
					}
					return &leaf.tlsCertificate, nil
				}
			}
			if mainCert != nil {
				return mainCert, nil
			}
			leaf, err := s.ensureManagedLeafCertificateForHost(host)
			if err != nil {
				return nil, err
			}
			return &leaf.tlsCertificate, nil
		},
	}, nil
}
