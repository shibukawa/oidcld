package config

import (
	"net"
	neturl "net/url"
	"strings"
)

func NormalizeIssuerForServe(issuer, port string, entraid *EntraIDConfig) string {
	issuer = synchronizeLocalIssuerPort(issuer, port)
	issuer = normalizeEntraIssuerPath(issuer, entraid)
	return issuer
}

func IssuerPathPrefix(issuer string) string {
	parsed, err := neturl.Parse(issuer)
	if err != nil {
		return ""
	}
	prefix := strings.TrimSuffix(parsed.Path, "/")
	if prefix == "" || prefix == "/" {
		return ""
	}
	return prefix
}

func HTTPMetadataIssuer(issuer, httpMetadataAddr string) string {
	parsed, err := neturl.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return ""
	}
	port := strings.TrimPrefix(strings.TrimSpace(httpMetadataAddr), ":")
	if port == "" {
		return ""
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return ""
	}
	parsed.Scheme = "http"
	parsed.Host = net.JoinHostPort(hostname, port)
	return parsed.String()
}

func IssuerURLParts(issuer string) (scheme string, hostname string, port string, ok bool) {
	parsed, err := neturl.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", "", false
	}

	scheme = parsed.Scheme
	hostname = parsed.Hostname()
	if hostname == "" {
		return "", "", "", false
	}
	port = parsed.Port()
	if port == "" {
		port = DefaultServePort(strings.EqualFold(scheme, "https"))
	}
	return scheme, hostname, port, true
}

func IssuerHostname(issuer string) string {
	_, hostname, _, ok := IssuerURLParts(issuer)
	if !ok {
		return ""
	}
	return hostname
}

func HostMatchesCertificateDomains(host string, domains []string) bool {
	for _, domain := range domains {
		if HostMatchesCertificateDomain(host, domain) {
			return true
		}
	}
	return false
}

func HostMatchesCertificateDomain(host, domain string) bool {
	host = strings.TrimSpace(host)
	domain = strings.TrimSpace(domain)
	if host == "" || domain == "" {
		return false
	}

	if hostIP := net.ParseIP(host); hostIP != nil {
		domainIP := net.ParseIP(strings.Trim(domain, "[]"))
		return domainIP != nil && hostIP.Equal(domainIP)
	}
	if net.ParseIP(strings.Trim(domain, "[]")) != nil {
		return false
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if strings.HasPrefix(domain, "*.") {
		suffix := strings.TrimPrefix(domain, "*.")
		if suffix == "" || host == suffix || !strings.HasSuffix(host, "."+suffix) {
			return false
		}
		prefix := strings.TrimSuffix(host, "."+suffix)
		return prefix != "" && !strings.Contains(prefix, ".")
	}

	return host == domain
}

func normalizeEntraIssuerPath(issuer string, entraid *EntraIDConfig) string {
	expectedPath := expectedEntraIssuerPath(entraid)
	if issuer == "" || expectedPath == "" {
		return issuer
	}

	parsed, err := neturl.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return issuer
	}

	currentPath := strings.TrimSuffix(parsed.Path, "/")
	if currentPath == expectedPath {
		return parsed.String()
	}
	if currentPath != "" && currentPath != "/" {
		return issuer
	}

	parsed.Path = expectedPath
	return parsed.String()
}

func expectedEntraIssuerPath(entraid *EntraIDConfig) string {
	if entraid == nil || entraid.TenantID == "" {
		return ""
	}

	tenantID := strings.Trim(entraid.TenantID, "/")
	if tenantID == "" {
		return ""
	}

	switch strings.ToLower(entraid.Version) {
	case "v1":
		return "/" + tenantID
	case "v2":
		return "/" + tenantID + "/v2.0"
	default:
		return ""
	}
}

func synchronizeLocalIssuerPort(issuer, port string) string {
	if issuer == "" || port == "" {
		return issuer
	}
	parsed, err := neturl.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return issuer
	}
	host := parsed.Hostname()
	if !isLocalLoopbackHost(host) {
		return issuer
	}
	parsed.Host = net.JoinHostPort(host, port)
	return parsed.String()
}

func isLocalLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
