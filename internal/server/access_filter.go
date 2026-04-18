package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

var defaultLocalAccessNetworks = []*net.IPNet{
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("fc00::/7"),
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
}

var (
	ErrAccessFilterInvalidAllowedNetwork   = errors.New("invalid access filter extra_allowed_ips entry")
	ErrAccessFilterInvalidRemoteAddr       = errors.New("invalid remote addr")
	ErrAccessFilterEmptyForwardedElement   = errors.New("empty Forwarded element")
	ErrAccessFilterMissingForwardedElement = errors.New("missing Forwarded element")
	ErrAccessFilterEmptyForwardedParameter = errors.New("empty Forwarded parameter")
	ErrAccessFilterInvalidForwardedParam   = errors.New("invalid Forwarded parameter")
	ErrAccessFilterEmptyXForwardedFor      = errors.New("empty X-Forwarded-For element")
	ErrAccessFilterMissingXForwardedFor    = errors.New("missing X-Forwarded-For element")
)

type compiledAccessFilter struct {
	enabled          bool
	maxForwardedHops int
	extraAllowedNets []*net.IPNet
}

type accessFilterStartupInfo struct {
	Enabled          bool
	ExtraAllowedIPs  int
	MaxForwardedHops int
}

type accessDecision struct {
	Allowed bool
	Reason  string

	ForwardedHops     int
	XForwardedForHops int
	MaxForwardedHops  int
}

func newCompiledAccessFilter(cfg *config.AccessFilterConfig) (*compiledAccessFilter, error) {
	if cfg == nil {
		cfg = config.DefaultAccessFilterConfig()
	}

	extraAllowedNets := make([]*net.IPNet, 0, len(cfg.ExtraAllowedIPs))
	for _, entry := range cfg.ExtraAllowedIPs {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrAccessFilterInvalidAllowedNetwork, entry, err)
		}
		extraAllowedNets = append(extraAllowedNets, ipNet)
	}

	return &compiledAccessFilter{
		enabled:          cfg.Enabled,
		maxForwardedHops: cfg.MaxForwardedHops,
		extraAllowedNets: extraAllowedNets,
	}, nil
}

func (f *compiledAccessFilter) startupInfo() accessFilterStartupInfo {
	if f == nil {
		return accessFilterStartupInfo{}
	}
	return accessFilterStartupInfo{
		Enabled:          f.enabled,
		ExtraAllowedIPs:  len(f.extraAllowedNets),
		MaxForwardedHops: f.maxForwardedHops,
	}
}

func (s *Server) accessFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision := s.evaluateAccess(r)
		if !decision.Allowed {
			s.logger.Warn("Access filter denied request",
				"reason", decision.Reason,
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, s.accessDeniedMessage(decision), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) evaluateAccess(r *http.Request) accessDecision {
	if s == nil || s.access == nil || !s.access.enabled {
		return accessDecision{Allowed: true}
	}

	forwardedHops, hasForwarded, err := countForwardedHeaderHops(r.Header)
	if err != nil {
		return accessDecision{Reason: "malformed_forward_header"}
	}
	xForwardedForHops, hasXForwardedFor, err := countXForwardedForHops(r.Header)
	if err != nil {
		return accessDecision{Reason: "malformed_forward_header"}
	}

	if hasForwarded || hasXForwardedFor {
		effectiveHops := max(forwardedHops, xForwardedForHops)
		if effectiveHops <= s.access.maxForwardedHops {
			return accessDecision{Allowed: true}
		}
		return accessDecision{
			Reason:            "forwarded_hops_exceeded",
			ForwardedHops:     forwardedHops,
			XForwardedForHops: xForwardedForHops,
			MaxForwardedHops:  s.access.maxForwardedHops,
		}
	}

	peerIP, err := remotePeerIP(r.RemoteAddr)
	if err != nil {
		return accessDecision{Reason: "peer_not_allowed"}
	}
	if s.access.isAllowedPeer(peerIP) {
		return accessDecision{Allowed: true}
	}
	return accessDecision{Reason: "peer_not_allowed"}
}

func (s *Server) accessDeniedMessage(decision accessDecision) string {
	switch decision.Reason {
	case "forwarded_hops_exceeded":
		effectiveHops := max(decision.ForwardedHops, decision.XForwardedForHops)
		return fmt.Sprintf(
			"Forbidden\n\nOIDCLD access_filter denied this request because the forwarded hop count exceeded the configured limit.\n\nConfigured max_forwarded_hops: %d\nObserved effective hops: %d\nForwarded header hops: %d\nX-Forwarded-For hops: %d\n\nAdjust access_filter.max_forwarded_hops if this proxy chain is expected.",
			decision.MaxForwardedHops,
			effectiveHops,
			decision.ForwardedHops,
			decision.XForwardedForHops,
		)
	case "malformed_forward_header":
		return "Forbidden\n\nOIDCLD access_filter denied this request because the forwarded headers were malformed."
	default:
		return http.StatusText(http.StatusForbidden)
	}
}

func (f *compiledAccessFilter) isAllowedPeer(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range defaultLocalAccessNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	for _, network := range f.extraAllowedNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func remotePeerIP(remoteAddr string) (net.IP, error) {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip := net.ParseIP(host)
		if ip != nil {
			return ip, nil
		}
	}

	trimmed := strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil, fmt.Errorf("%w %q", ErrAccessFilterInvalidRemoteAddr, remoteAddr)
	}
	return ip, nil
}

func countForwardedHeaderHops(header http.Header) (int, bool, error) {
	values, ok := header["Forwarded"]
	if !ok {
		return 0, false, nil
	}

	count := 0
	for _, raw := range values {
		for part := range strings.SplitSeq(raw, ",") {
			element := strings.TrimSpace(part)
			if element == "" {
				return 0, true, ErrAccessFilterEmptyForwardedElement
			}
			if err := validateForwardedElement(element); err != nil {
				return 0, true, err
			}
			count++
		}
	}
	if count == 0 {
		return 0, true, ErrAccessFilterMissingForwardedElement
	}
	return count, true, nil
}

func validateForwardedElement(element string) error {
	for part := range strings.SplitSeq(element, ";") {
		token := strings.TrimSpace(part)
		if token == "" {
			return ErrAccessFilterEmptyForwardedParameter
		}
		key, value, found := strings.Cut(token, "=")
		if !found || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w %q", ErrAccessFilterInvalidForwardedParam, token)
		}
	}
	return nil
}

func countXForwardedForHops(header http.Header) (int, bool, error) {
	values, ok := header["X-Forwarded-For"]
	if !ok {
		return 0, false, nil
	}

	count := 0
	for _, raw := range values {
		for part := range strings.SplitSeq(raw, ",") {
			token := strings.TrimSpace(part)
			if token == "" {
				return 0, true, ErrAccessFilterEmptyXForwardedFor
			}
			count++
		}
	}
	if count == 0 {
		return 0, true, ErrAccessFilterMissingXForwardedFor
	}
	return count, true, nil
}

func mustParseCIDR(value string) *net.IPNet {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return network
}
