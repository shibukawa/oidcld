package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

var defaultLocalAccessNetworks = []*net.IPNet{
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
}

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

func newCompiledAccessFilter(cfg *config.AccessFilterConfig) (*compiledAccessFilter, error) {
	if cfg == nil {
		cfg = config.DefaultAccessFilterConfig()
	}

	extraAllowedNets := make([]*net.IPNet, 0, len(cfg.ExtraAllowedIPs))
	for _, entry := range cfg.ExtraAllowedIPs {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("parse access filter extra_allowed_ips entry %q: %w", entry, err)
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
		allowed, reason := s.evaluateAccess(r)
		if !allowed {
			s.logger.Warn("Access filter denied request",
				"reason", reason,
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) evaluateAccess(r *http.Request) (bool, string) {
	if s == nil || s.access == nil || !s.access.enabled {
		return true, ""
	}

	forwardedHops, hasForwarded, err := countForwardedHeaderHops(r.Header)
	if err != nil {
		return false, "malformed_forward_header"
	}
	xForwardedForHops, hasXForwardedFor, err := countXForwardedForHops(r.Header)
	if err != nil {
		return false, "malformed_forward_header"
	}

	if hasForwarded || hasXForwardedFor {
		effectiveHops := max(forwardedHops, xForwardedForHops)
		if effectiveHops <= s.access.maxForwardedHops {
			return true, ""
		}
		return false, "forwarded_hops_exceeded"
	}

	peerIP, err := remotePeerIP(r.RemoteAddr)
	if err != nil {
		return false, "peer_not_allowed"
	}
	if s.access.isAllowedPeer(peerIP) {
		return true, ""
	}
	return false, "peer_not_allowed"
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
		return nil, fmt.Errorf("invalid remote addr %q", remoteAddr)
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
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			element := strings.TrimSpace(part)
			if element == "" {
				return 0, true, fmt.Errorf("empty Forwarded element")
			}
			if err := validateForwardedElement(element); err != nil {
				return 0, true, err
			}
			count++
		}
	}
	if count == 0 {
		return 0, true, fmt.Errorf("missing Forwarded element")
	}
	return count, true, nil
}

func validateForwardedElement(element string) error {
	parts := strings.Split(element, ";")
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			return fmt.Errorf("empty Forwarded parameter")
		}
		key, value, found := strings.Cut(token, "=")
		if !found || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return fmt.Errorf("invalid Forwarded parameter %q", token)
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
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			token := strings.TrimSpace(part)
			if token == "" {
				return 0, true, fmt.Errorf("empty X-Forwarded-For element")
			}
			count++
		}
	}
	if count == 0 {
		return 0, true, fmt.Errorf("missing X-Forwarded-For element")
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
