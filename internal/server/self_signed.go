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
	"sort"
	"strings"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
)

var (
	ErrSelfSignedConflictTLSProvided      = errors.New("self-signed TLS is configured and TLS certificate/key were also provided; choose one method")
	ErrCertificateAuthorityConfigMissing  = errors.New("certificate authority configuration is not available")
	ErrIssuerHostNotCoveredByCADomains    = errors.New("oidc.iss host is not covered by certificate_authority.domains")
	ErrManagedWildcardDomainNotConfigured = errors.New("managed wildcard domain is not configured")
	ErrManagedWildcardDomainLabelRequired = errors.New("domain label is required")
	ErrManagedWildcardDomainLabelInvalid  = errors.New("domain label must not contain dots or wildcard characters")
	ErrManagedWildcardDomainNotCovered    = errors.New("domain is not covered by the managed wildcard domain")
	ErrRootCACertificateDecode            = errors.New("failed to decode root CA certificate")
	ErrCAPEMDecode                        = errors.New("failed to decode CA PEM")
	ErrCAKeyPEMDecode                     = errors.New("failed to decode CA key PEM")
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

type managedLeafCertificateRequest struct {
	Domain       string
	Organization string
	NotBefore    time.Time
	TTL          time.Duration
}

type managedIssuedLeafInfo struct {
	subject      string
	organization string
	serial       string
	notBefore    time.Time
	notAfter     time.Time
	domain       string
	certFile     string
	keyFile      string
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

func generateManagedLeafCertificateFromRequest(request managedLeafCertificateRequest, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caCertPEM []byte) (*managedLeafCertificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf certificate key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf certificate serial number: %w", err)
	}

	domain := strings.TrimSpace(request.Domain)
	if domain == "" {
		domain = "localhost"
	}
	organization := strings.TrimSpace(request.Organization)
	if organization == "" {
		organization = "OIDCLD"
	}
	notBefore := request.NotBefore.UTC()
	if notBefore.IsZero() {
		notBefore = time.Now().UTC().Add(-time.Minute)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{organization},
		},
		NotBefore:          notBefore,
		NotAfter:           notBefore.Add(request.TTL),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	addManagedCertificateDomains(template, []string{domain})

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

func generateManagedLeafCertificate(cfg *config.Config, host string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caCertPEM []byte) (*managedLeafCertificate, error) {
	leafTTL, err := time.ParseDuration(strings.TrimSpace(cfg.CertificateAuthority.LeafCertTTL))
	if err != nil {
		return nil, fmt.Errorf("invalid self-signed leaf certificate TTL: %w", err)
	}

	return generateManagedLeafCertificateFromRequest(managedLeafCertificateRequest{
		Domain:       managedLeafCommonName(cfg, host, managedLeafIssuedDomains(cfg, host)),
		Organization: "OIDCLD",
		NotBefore:    time.Now().UTC().Add(-time.Minute),
		TTL:          leafTTL,
	}, caCert, caKey, caCertPEM)
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

func firstManagedWildcardDomain(domains []string) (string, bool) {
	for _, domain := range domains {
		trimmed := strings.TrimSpace(domain)
		if _, ok := strings.CutPrefix(trimmed, "*."); ok {
			return trimmed, true
		}
	}
	return "", false
}

func managedLeafIssuedDomains(cfg *config.Config, host string) []string {
	if cfg == nil {
		return []string{"localhost"}
	}
	if trimmedHost := strings.TrimSpace(host); trimmedHost != "" {
		return []string{trimmedHost}
	}
	if issuerHost := config.IssuerHostname(cfg.OIDC.Issuer); issuerHost != "" {
		return []string{issuerHost}
	}
	return []string{"localhost"}
}

func managedLeafCommonName(cfg *config.Config, host string, domains []string) string {
	if cfg == nil {
		return firstManagedDomain(domains)
	}
	if trimmedHost := strings.TrimSpace(host); trimmedHost != "" && config.HostMatchesCertificateDomains(trimmedHost, domains) {
		return trimmedHost
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
		return &issuerHostCoverageError{host: host, scope: "certificate_authority.domains", inner: ErrIssuerHostNotCoveredByCADomains}
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
	infos := make([]managedIssuedLeafInfo, 0, 4)
	seenSerials := map[string]struct{}{}
	leaf, err := s.ensureManagedLeafCertificate()
	if err == nil {
		info := managedIssuedLeafInfo{
			subject:      leaf.certificate.Subject.String(),
			organization: firstManagedOrganization(leaf.certificate.Subject.Organization),
			serial:       leaf.certificate.SerialNumber.String(),
			notBefore:    leaf.certificate.NotBefore,
			notAfter:     leaf.certificate.NotAfter,
			domain:       firstManagedDomain(leaf.certificate.DNSNames),
		}
		infos = append(infos, info)
		seenSerials[info.serial] = struct{}{}
	}

	s.managedLeafMu.Lock()
	for host, item := range s.managedLeaves {
		if item == nil {
			continue
		}
		serial := item.certificate.SerialNumber.String()
		if _, exists := seenSerials[serial]; exists {
			continue
		}
		infos = append(infos, managedIssuedLeafInfo{
			subject:      item.certificate.Subject.String(),
			organization: firstManagedOrganization(item.certificate.Subject.Organization),
			serial:       serial,
			notBefore:    item.certificate.NotBefore,
			notAfter:     item.certificate.NotAfter,
			domain:       host,
		})
		seenSerials[serial] = struct{}{}
	}
	s.managedLeafMu.Unlock()

	persistedInfos, persistedErr := loadPersistedManagedLeafCertificateInfos(s.config)
	if persistedErr != nil && len(infos) == 0 {
		return nil, persistedErr
	}
	for _, info := range persistedInfos {
		if _, exists := seenSerials[info.serial]; exists {
			continue
		}
		infos = append(infos, info)
		seenSerials[info.serial] = struct{}{}
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].notBefore.After(infos[j].notBefore)
	})

	result := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		result = append(result, map[string]any{
			"subject":      info.subject,
			"organization": info.organization,
			"serial":       info.serial,
			"notBefore":    info.notBefore.Format(time.RFC3339),
			"notAfter":     info.notAfter.Format(time.RFC3339),
			"domain":       info.domain,
			"certFile":     info.certFile,
			"keyFile":      info.keyFile,
		})
	}
	return result, nil
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

func managedWildcardHost(domains []string, domainLabel string) (string, error) {
	wildcardDomain, ok := firstManagedWildcardDomain(domains)
	if !ok {
		return "", ErrManagedWildcardDomainNotConfigured
	}
	suffix, _ := strings.CutPrefix(wildcardDomain, "*.")
	label := strings.TrimSpace(domainLabel)
	if label == "" {
		return "", ErrManagedWildcardDomainLabelRequired
	}
	if strings.Contains(label, ".") || strings.Contains(label, "*") {
		return "", ErrManagedWildcardDomainLabelInvalid
	}
	host := label + "." + suffix
	if !config.HostMatchesCertificateDomain(host, wildcardDomain) {
		return "", fmt.Errorf("%w: %q is not covered by %q", ErrManagedWildcardDomainNotCovered, host, wildcardDomain)
	}
	return host, nil
}

func managedIssuedLeafsDir(cfg *config.Config) string {
	if cfg == nil || cfg.CertificateAuthority == nil {
		return ""
	}
	return filepath.Join(resolveManagedTLSPath(cfg.SourceDir(), cfg.CertificateAuthority.CADir), "issued")
}

func persistManagedLeafCertificate(cfg *config.Config, leaf *managedLeafCertificate) (managedIssuedLeafInfo, error) {
	issuedDir := managedIssuedLeafsDir(cfg)
	if issuedDir == "" {
		return managedIssuedLeafInfo{}, ErrCertificateAuthorityConfigMissing
	}
	entryDir := filepath.Join(issuedDir, leaf.certificate.SerialNumber.String())
	if err := os.MkdirAll(entryDir, 0o755); err != nil {
		return managedIssuedLeafInfo{}, fmt.Errorf("failed to create issued leaf directory: %w", err)
	}

	certFile := filepath.Join(entryDir, "certificate.pem")
	keyFile := filepath.Join(entryDir, "private-key.pem")
	chainFile := filepath.Join(entryDir, "chain.pem")
	if err := os.WriteFile(certFile, leaf.certPEM, 0o644); err != nil {
		return managedIssuedLeafInfo{}, fmt.Errorf("failed to write issued certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, leaf.keyPEM, 0o600); err != nil {
		return managedIssuedLeafInfo{}, fmt.Errorf("failed to write issued private key: %w", err)
	}
	if err := os.WriteFile(chainFile, leaf.chainPEM, 0o644); err != nil {
		return managedIssuedLeafInfo{}, fmt.Errorf("failed to write issued chain: %w", err)
	}

	return managedIssuedLeafInfo{
		subject:      leaf.certificate.Subject.String(),
		organization: firstManagedOrganization(leaf.certificate.Subject.Organization),
		serial:       leaf.certificate.SerialNumber.String(),
		notBefore:    leaf.certificate.NotBefore,
		notAfter:     leaf.certificate.NotAfter,
		domain:       firstManagedDomain(leaf.certificate.DNSNames),
		certFile:     certFile,
		keyFile:      keyFile,
	}, nil
}

func loadPersistedManagedLeafCertificateInfos(cfg *config.Config) ([]managedIssuedLeafInfo, error) {
	issuedDir := managedIssuedLeafsDir(cfg)
	if issuedDir == "" {
		return nil, ErrCertificateAuthorityConfigMissing
	}
	entries, err := os.ReadDir(issuedDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	infos := make([]managedIssuedLeafInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		certFile := filepath.Join(issuedDir, entry.Name(), "certificate.pem")
		keyFile := filepath.Join(issuedDir, entry.Name(), "private-key.pem")
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		infos = append(infos, managedIssuedLeafInfo{
			subject:      cert.Subject.String(),
			organization: firstManagedOrganization(cert.Subject.Organization),
			serial:       cert.SerialNumber.String(),
			notBefore:    cert.NotBefore,
			notAfter:     cert.NotAfter,
			domain:       firstManagedDomain(cert.DNSNames),
			certFile:     certFile,
			keyFile:      keyFile,
		})
	}
	return infos, nil
}

func (s *Server) ensureManagedLeafCertificate() (*managedLeafCertificate, error) {
	return s.ensureManagedLeafCertificateForHost(config.IssuerHostname(s.config.OIDC.Issuer))
}

func (s *Server) ensureManagedLeafCertificateForHost(host string) (*managedLeafCertificate, error) {
	s.managedLeafMu.Lock()
	defer s.managedLeafMu.Unlock()

	if s.managedLeaves == nil {
		s.managedLeaves = map[string]*managedLeafCertificate{}
	}
	if s.config == nil || s.config.CertificateAuthority == nil {
		return nil, ErrCertificateAuthorityConfigMissing
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = config.IssuerHostname(s.config.OIDC.Issuer)
	}
	if host == "" {
		host = "localhost"
	}

	if leaf := s.managedLeaves[host]; leaf != nil && time.Now().Before(leaf.certificate.NotAfter) {
		return leaf, nil
	}
	if !config.HostMatchesCertificateDomains(host, s.config.CertificateAuthority.Domains) {
		return nil, &issuerHostCoverageError{host: host, scope: "certificate_authority.domains", inner: ErrIssuerHostNotCoveredByCADomains}
	}
	if err := validateManagedIssuerDomains(s.config); err != nil && host == config.IssuerHostname(s.config.OIDC.Issuer) {
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
	leaf, err := generateManagedLeafCertificate(s.config, host, caCert, caKey, caCertPEM)
	if err != nil {
		return nil, err
	}
	s.managedLeaves[host] = leaf
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
