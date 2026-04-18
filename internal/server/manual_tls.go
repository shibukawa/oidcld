package server

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

func ValidateIssuerMatchesCertificate(issuer, certFile string) error {
	scheme, host, _, ok := config.IssuerURLParts(issuer)
	if !ok || !strings.EqualFold(scheme, "https") {
		return nil
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read TLS certificate %q: %w", certFile, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode TLS certificate %q", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse TLS certificate %q: %w", certFile, err)
	}

	domains := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		domains = append(domains, ip.String())
	}

	if len(domains) == 0 {
		if cert.Subject.CommonName != "" && config.HostMatchesCertificateDomain(host, cert.Subject.CommonName) {
			return nil
		}
		return fmt.Errorf("oidc.iss host %q is not covered by the TLS certificate SAN or CN", host)
	}

	if !config.HostMatchesCertificateDomains(host, domains) {
		return fmt.Errorf("oidc.iss host %q is not covered by the TLS certificate SAN", host)
	}

	return nil
}
