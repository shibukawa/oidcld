package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
)

var (
	ErrSelfSignedConflictTLSProvided     = errors.New("self-signed TLS is configured and TLS certificate/key were also provided; choose one method")
	ErrCertificateAuthorityConfigMissing = errors.New("certificate authority configuration is not available")
	ErrIssuerHostNotCoveredByCADomains   = errors.New("oidc.iss host is not covered by certificate_authority.domains")
	ErrRootCACertificateDecode           = errors.New("failed to decode root CA certificate")
	ErrCAPEMDecode                       = errors.New("failed to decode CA PEM")
	ErrCAKeyPEMDecode                    = errors.New("failed to decode CA key PEM")
)

type managedTLSBundle struct {
	CACertPath string
	CAKeyPath  string
}

type managedLeafCertificate struct {
	tlsCertificate tls.Certificate
	certificate    *x509.Certificate
	certPEM        []byte
	keyPEM         []byte
	chainPEM       []byte
}

func ensureManagedSelfSignedTLSAssets(cfg *config.Config) (*managedTLSBundle, error) {
	if cfg == nil || cfg.CertificateAuthority == nil {
		return nil, ErrCertificateAuthorityConfigMissing
	}

	caDir := resolveManagedTLSPath(cfg.SourceDir(), cfg.CertificateAuthority.CADir)
	bundle := &managedTLSBundle{
		CACertPath: filepath.Join(caDir, "root-ca.pem"),
		CAKeyPath:  filepath.Join(caDir, "root-ca-key.pem"),
	}

	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create self-signed TLS directory: %w", err)
	}

	caCert, caKey, caCertPEM, err := ensureManagedRootCA(cfg, bundle)
	if err != nil {
		return nil, err
	}
	_ = caCert
	_ = caKey
	_ = caCertPEM

	return bundle, nil
}

func ensureManagedRootCA(cfg *config.Config, bundle *managedTLSBundle) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	if cert, key, certPEM, err := loadManagedCA(bundle); err == nil {
		if time.Now().Before(cert.NotAfter) {
			return cert, key, certPEM, nil
		}
	}

	caTTL, err := time.ParseDuration(strings.TrimSpace(cfg.CertificateAuthority.CACertTTL))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid self-signed CA TTL: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate root CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate root CA serial number: %w", err)
	}

	now := time.Now().UTC().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "OIDCLD Development Root CA",
			Organization: []string{"OIDCLD"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal root CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(bundle.CACertPath, certPEM, 0o644); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write root CA certificate: %w", err)
	}
	if err := os.WriteFile(bundle.CAKeyPath, keyPEM, 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write root CA key: %w", err)
	}

	return cert, privateKey, certPEM, nil
}

func generateManagedLeafCertificate(cfg *config.Config, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caCertPEM []byte) (*managedLeafCertificate, error) {
	leafTTL, err := time.ParseDuration(strings.TrimSpace(cfg.CertificateAuthority.LeafCertTTL))
	if err != nil {
		return nil, fmt.Errorf("invalid self-signed leaf certificate TTL: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf certificate key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf certificate serial number: %w", err)
	}

	domains := managedLeafIssuedDomains(cfg)
	now := time.Now().UTC().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   managedLeafCommonName(cfg, domains),
			Organization: []string{"OIDCLD"},
		},
		NotBefore:          now,
		NotAfter:           now.Add(leafTTL),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	addManagedCertificateDomains(template, domains)

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	chain := append(append([]byte{}, leafCertPEM...), caCertPEM...)
	tlsCertificate, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load leaf key pair: %w", err)
	}
	return &managedLeafCertificate{
		tlsCertificate: tlsCertificate,
		certificate:    leafCert,
		certPEM:        leafCertPEM,
		keyPEM:         keyPEM,
		chainPEM:       chain,
	}, nil
}

func addManagedCertificateDomains(template *x509.Certificate, domains []string) {
	seenDNS := map[string]struct{}{}
	seenIP := map[string]struct{}{}
	for _, domain := range domains {
		trimmed := strings.TrimSpace(domain)
		if trimmed == "" {
			continue
		}
		if ip := net.ParseIP(trimmed); ip != nil {
			key := ip.String()
			if _, ok := seenIP[key]; ok {
				continue
			}
			seenIP[key] = struct{}{}
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		if _, ok := seenDNS[trimmed]; ok {
			continue
		}
		seenDNS[trimmed] = struct{}{}
		template.DNSNames = append(template.DNSNames, trimmed)
	}
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		template.DNSNames = []string{"localhost"}
	}
}

func firstManagedDomain(domains []string) string {
	for _, domain := range domains {
		trimmed := strings.TrimSpace(domain)
		if trimmed != "" {
			return trimmed
		}
	}
	return "localhost"
}

func managedLeafIssuedDomains(cfg *config.Config) []string {
	if cfg == nil {
		return []string{"localhost"}
	}
	if issuerHost := config.IssuerHostname(cfg.OIDC.Issuer); issuerHost != "" {
		return []string{issuerHost}
	}
	return []string{"localhost"}
}

func managedLeafCommonName(cfg *config.Config, domains []string) string {
	if cfg == nil {
		return firstManagedDomain(domains)
	}
	if issuerHost := config.IssuerHostname(cfg.OIDC.Issuer); issuerHost != "" && config.HostMatchesCertificateDomains(issuerHost, domains) {
		return issuerHost
	}
	for _, domain := range domains {
		trimmed := strings.TrimSpace(domain)
		if trimmed == "" || strings.Contains(trimmed, "*") || net.ParseIP(trimmed) != nil {
			continue
		}
		return trimmed
	}
	return firstManagedDomain(domains)
}

func validateManagedIssuerDomains(cfg *config.Config) error {
	if cfg == nil || cfg.CertificateAuthority == nil {
		return ErrCertificateAuthorityConfigMissing
	}
	if scheme, host, _, ok := config.IssuerURLParts(cfg.OIDC.Issuer); ok && strings.EqualFold(scheme, "https") && !config.HostMatchesCertificateDomains(host, cfg.CertificateAuthority.Domains) {
		return fmt.Errorf("%w: %q", ErrIssuerHostNotCoveredByCADomains, host)
	}
	return nil
}

func resolveManagedTLSPath(sourceDir, rawPath string) string {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		trimmed = "./tls"
	}
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed)
	}
	if strings.TrimSpace(sourceDir) != "" {
		return filepath.Clean(filepath.Join(sourceDir, trimmed))
	}
	return filepath.Clean(trimmed)
}

func (s *Server) loadManagedRootCAInfo() (map[string]any, error) {
	bundle, err := ensureManagedSelfSignedTLSAssets(s.config)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(bundle.CACertPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, ErrRootCACertificateDecode
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"subject":     cert.Subject.String(),
		"serial":      cert.SerialNumber.String(),
		"notBefore":   cert.NotBefore.Format(time.RFC3339),
		"notAfter":    cert.NotAfter.Format(time.RFC3339),
		"certificate": bundle.CACertPath,
	}, nil
}

func (s *Server) loadManagedLeafCertificateInfos() ([]map[string]any, error) {
	leaf, err := s.ensureManagedLeafCertificate()
	if err != nil {
		return nil, err
	}
	return []map[string]any{{
		"subject":      leaf.certificate.Subject.String(),
		"organization": firstManagedOrganization(leaf.certificate.Subject.Organization),
		"serial":       leaf.certificate.SerialNumber.String(),
		"notBefore":    leaf.certificate.NotBefore.Format(time.RFC3339),
		"notAfter":     leaf.certificate.NotAfter.Format(time.RFC3339),
		"domain":       firstManagedDomain(leaf.certificate.DNSNames),
	}}, nil
}

func firstManagedOrganization(values []string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (s *Server) ensureManagedLeafCertificate() (*managedLeafCertificate, error) {
	s.managedLeafMu.Lock()
	defer s.managedLeafMu.Unlock()

	if s.managedLeaf != nil && time.Now().Before(s.managedLeaf.certificate.NotAfter) {
		return s.managedLeaf, nil
	}
	if err := validateManagedIssuerDomains(s.config); err != nil {
		return nil, err
	}

	bundle, err := ensureManagedSelfSignedTLSAssets(s.config)
	if err != nil {
		return nil, err
	}
	caCert, caKey, caCertPEM, err := loadManagedCA(bundle)
	if err != nil {
		return nil, err
	}
	leaf, err := generateManagedLeafCertificate(s.config, caCert, caKey, caCertPEM)
	if err != nil {
		return nil, err
	}
	s.managedLeaf = leaf
	return leaf, nil
}

func loadManagedCA(bundle *managedTLSBundle) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certPEM, err := os.ReadFile(bundle.CACertPath)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := os.ReadFile(bundle.CAKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, nil, ErrCAPEMDecode
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, nil, ErrCAKeyPEMDecode
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, certPEM, nil
}
