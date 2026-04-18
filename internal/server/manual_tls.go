package server

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

var (
	ErrTLSCertificateDecode             = errors.New("failed to decode TLS certificate")
	ErrIssuerHostNotCoveredByTLSCertCN  = errors.New("oidc.iss host is not covered by the TLS certificate SAN or CN")
	ErrIssuerHostNotCoveredByTLSCertSAN = errors.New("oidc.iss host is not covered by the TLS certificate SAN")
)

type issuerHostCoverageError struct {
	host  string
	scope string
	inner error
}

func (e *issuerHostCoverageError) Error() string {
	return fmt.Sprintf("oidc.iss host %q is not covered by %s", e.host, e.scope)
}

func (e *issuerHostCoverageError) Unwrap() error {
	return e.inner
}

func ValidateIssuerMatchesCertificate(issuer, certFile string) error {
	scheme, host, _, ok := config.IssuerURLParts(issuer)
	if !ok || !strings.EqualFold(scheme, "https") {
		return nil
	}
	return validateHostMatchesCertificate(host, certFile)
}

func validateHostMatchesCertificate(host, certFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read TLS certificate %q: %w", certFile, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("%w: %q", ErrTLSCertificateDecode, certFile)
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
		return &issuerHostCoverageError{host: host, scope: "the TLS certificate SAN or CN", inner: ErrIssuerHostNotCoveredByTLSCertCN}
	}

	if !config.HostMatchesCertificateDomains(host, domains) {
		return &issuerHostCoverageError{host: host, scope: "the TLS certificate SAN", inner: ErrIssuerHostNotCoveredByTLSCertSAN}
	}

	return nil
}
