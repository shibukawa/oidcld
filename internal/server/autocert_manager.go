package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/shibukawa/oidcld/internal/config"
)

// loggingCache wraps an autocert.Cache and logs Get/Put/Delete operations for diagnostics.
type loggingCache struct {
	inner autocert.Cache
}

func (lc *loggingCache) Get(ctx context.Context, key string) ([]byte, error) {
	log.Printf("[autocert][cache] Get key=%s", key)
	data, err := lc.inner.Get(ctx, key)
	if err != nil {
		log.Printf("[autocert][cache] Get key=%s error=%v", key, err)
	} else {
		log.Printf("[autocert][cache] Get key=%s returned %d bytes", key, len(data))
	}
	return data, err
}

func (lc *loggingCache) Put(ctx context.Context, key string, data []byte) error {
	log.Printf("[autocert][cache] Put key=%s bytes=%d", key, len(data))
	err := lc.inner.Put(ctx, key, data)
	if err != nil {
		log.Printf("[autocert][cache] Put key=%s error=%v", key, err)
	} else {
		log.Printf("[autocert][cache] Put key=%s OK", key)
	}
	return err
}

func (lc *loggingCache) Delete(ctx context.Context, key string) error {
	log.Printf("[autocert][cache] Delete key=%s", key)
	err := lc.inner.Delete(ctx, key)
	if err != nil {
		log.Printf("[autocert][cache] Delete key=%s error=%v", key, err)
	} else {
		log.Printf("[autocert][cache] Delete key=%s OK", key)
	}
	return err
}

// AutocertManager manages automatic HTTPS certificate acquisition and renewal.
type AutocertManager struct {
	config  *config.AutocertConfig
	manager *autocert.Manager
	logger  *Logger
}

// NewAutocertManager creates a new autocert manager with the given configuration.
func NewAutocertManager(cfg *config.AutocertConfig, logger *Logger) (*AutocertManager, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("autocert is not enabled")
	}

	// Validate configuration
	tempConfig := &config.Config{Autocert: cfg}
	if err := tempConfig.ValidateAutocertConfig(); err != nil {
		return nil, fmt.Errorf("invalid autocert configuration: %w", err)
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory %s: %w", cfg.CacheDir, err)
	}

	// Create autocert manager
	dirCache := autocert.DirCache(cfg.CacheDir)
	manager := &autocert.Manager{
		Cache:      &loggingCache{inner: dirCache},
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
	}

	// Configure ACME client
	// Use configured ACME server or default to Let's Encrypt production
	acmeServer := cfg.ACMEServer
	if acmeServer == "" {
		acmeServer = "https://acme-v02.api.letsencrypt.org/directory"
	}
	manager.Client = &acme.Client{
		DirectoryURL: acmeServer,
	}

	// Apply InsecureSkipVerify if configured
	if cfg.InsecureSkipVerify {
		manager.Client.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	am := &AutocertManager{
		config:  cfg,
		manager: manager,
		logger:  logger,
	}

	return am, nil
}

// GetTLSConfig returns a TLS configuration that uses autocert for certificate management.
func (am *AutocertManager) GetTLSConfig() *tls.Config {
	config := am.manager.TLSConfig()
	// Override GetCertificate to use our custom method with logging
	config.GetCertificate = am.GetCertificate
	return config
}

// HTTPHandler returns an HTTP handler for ACME HTTP-01 challenges.
func (am *AutocertManager) HTTPHandler(fallback http.Handler) http.Handler {
	return am.manager.HTTPHandler(fallback)
}

// GetCertificate returns a certificate for the given hello info.
func (am *AutocertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName

	cert, err := am.manager.GetCertificate(hello)
	if err != nil {
		log.Printf("[autocert] Failed to get certificate for %s: %v", domain, err)
		return nil, err
	}

	// Determine certificate serial for deduplicated logging
	serial := ""
	if cert.Leaf != nil {
		serial = cert.Leaf.SerialNumber.String()
	} else if len(cert.Certificate) > 0 {
		if c0, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			serial = c0.SerialNumber.String()
		}
	}

	// Emit plain log for every certificate obtain event so operators can see all
	if cert.Leaf != nil {
		log.Printf("[autocert] Certificate obtained: %s serial=%s expires=%s", hello.ServerName, serial, cert.Leaf.NotAfter.Format("2006-01-02 15:04:05"))
	} else {
		log.Printf("[autocert] Certificate obtained: %s serial=%s", hello.ServerName, serial)
	}

	// Diagnostic: if using DirCache, list files in the cache directory so we can
	// see whether the certificate was written to disk.
	// Try to unwrap loggingCache to get the underlying DirCache path, if present.
	var cachePath string
	switch c := am.manager.Cache.(type) {
	case *loggingCache:
		if dc, ok := c.inner.(autocert.DirCache); ok {
			cachePath = string(dc)
		}
	case autocert.DirCache:
		cachePath = string(c)
	}
	if cachePath != "" {
		if entries, err := os.ReadDir(cachePath); err == nil {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			log.Printf("[autocert] cacheDir=%s entries=%v", cachePath, names)
		} else {
			log.Printf("[autocert] failed to read cacheDir %s: %v", cachePath, err)
		}
	} else {
		log.Printf("[autocert] cache implementation is not DirCache: %T", am.manager.Cache)
	}
	return cert, nil
}

// StartRenewalMonitor starts a background goroutine that monitors certificate expiration
// and triggers renewal when certificates are close to expiring.
func (am *AutocertManager) StartRenewalMonitor(ctx context.Context) {
	go am.renewalMonitor(ctx)
}

// TriggerInitialObtain attempts to obtain certificates for all configured domains
// once at startup. It performs obtains sequentially and returns an error when
// an obtain fails so the caller can fail fast on misconfiguration.
func (am *AutocertManager) TriggerInitialObtain(ctx context.Context) error {
	// Small delay to allow server to finish startup tasks if needed
	time.Sleep(1 * time.Second)

	for _, domain := range am.config.Domains {
		select {
		case <-ctx.Done():
			log.Printf("[autocert] Initial certificate obtain canceled")
			return ctx.Err()
		default:
		}

		log.Printf("[autocert] Attempting initial certificate obtain for %s", domain)

		// Rely on manager.GetCertificate which will consult the cache internally.

		hello := &tls.ClientHelloInfo{ServerName: domain}
		_, err := am.manager.GetCertificate(hello)
		if err != nil {
			log.Printf("[autocert] Initial certificate obtain failed for %s: %v", domain, err)
			return err
		}

		log.Printf("[autocert] Initial certificate obtained for %s", domain)

		// Small pause between domains to avoid hammering ACME server
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

// renewalMonitor runs in the background and checks for certificates that need renewal.
func (am *AutocertManager) renewalMonitor(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	log.Printf("[autocert] Started certificate renewal monitor (checking every 24 hours)")

	for {
		select {
		case <-ctx.Done():
			log.Printf("[autocert] Certificate renewal monitor stopped")
			return
		case <-ticker.C:
			am.checkAndRenewCertificates(ctx)
		}
	}
}

// checkAndRenewCertificates checks all configured domains for certificate expiration
// and renews certificates that are close to expiring.
func (am *AutocertManager) checkAndRenewCertificates(ctx context.Context) {
	for _, domain := range am.config.Domains {
		// Diagnostic: log config snapshot for this cycle
		log.Printf("[autocert] Renewal check triggered for domain=%s (ACME=%s, InsecureSkipVerify=%v, RenewalThresholdDays=%d)",
			domain, am.config.ACMEServer, am.config.InsecureSkipVerify, am.config.RenewalThreshold)
		am.checkDomainCertificate(ctx, domain)
	}
}

// checkDomainCertificate checks a single domain's certificate and renews if necessary.
func (am *AutocertManager) checkDomainCertificate(ctx context.Context, domain string) {
	log.Printf("[autocert] Checking certificate for domain=%s", domain)

	// Diagnostic: log which cache dir and host policy
	log.Printf("[autocert] cacheDir=%s, hostPolicy=%v", am.config.CacheDir, am.config.Domains)

	// Obtain the current certificate via manager.GetCertificate.
	// Rationale: autocert writes multiple variant keys (domain+token, domain+rsa) and
	// may delete token files quickly; probing a single "domain" cache key returns
	// false misses. Using manager.GetCertificate avoids relying on internal cache key
	// layout and gives us the authoritative certificate (or triggers obtain when
	// necessary).
	hello := &tls.ClientHelloInfo{ServerName: domain}
	tlsCert, err := am.manager.GetCertificate(hello)
	if err != nil {
		log.Printf("[autocert] Failed to retrieve certificate for %s: %v", domain, err)
		return
	}

	if tlsCert == nil {
		log.Printf("[autocert] No certificate returned for %s", domain)
		return
	}

	if len(tlsCert.Certificate) == 0 {
		log.Printf("[autocert] Empty certificate chain for %s", domain)
		return
	}

	// Derive expiration date safely: prefer Leaf, otherwise parse first certificate
	var expiresAt time.Time
	if tlsCert.Leaf != nil {
		expiresAt = tlsCert.Leaf.NotAfter
		log.Printf("[autocert] Using tlsCert.Leaf for %s, expires=%s", domain, expiresAt.Format(time.RFC3339))
	} else {
		cert0, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			log.Printf("[autocert] Failed to parse x509 certificate for %s: %v", domain, err)
			return
		}
		expiresAt = cert0.NotAfter
		log.Printf("[autocert] Parsed x509 certificate for %s, expires=%s", domain, expiresAt.Format(time.RFC3339))
	}

	// Diagnostic: log certificate serial and issuer if available
	if tlsCert.Leaf != nil {
		log.Printf("[autocert] Certificate details for %s: serial=%s issuer=%s", domain, tlsCert.Leaf.SerialNumber.String(), tlsCert.Leaf.Issuer.String())
	}

	// Check if certificate needs renewal
	renewalThreshold := time.Duration(am.config.RenewalThreshold) * 24 * time.Hour
	log.Printf("[autocert] Renewal threshold (days) = %d, duration=%v", am.config.RenewalThreshold, renewalThreshold)
	timeUntilExpiry := time.Until(expiresAt)
	log.Printf("[autocert] Time until expiry for %s = %v", domain, timeUntilExpiry)

	// Diagnostic: compute days to expiry and log
	daysToExpiry := int(timeUntilExpiry.Hours() / 24)
	log.Printf("[autocert] Days to expiry for %s = %d", domain, daysToExpiry)

	if timeUntilExpiry <= renewalThreshold {
		log.Printf("[autocert] Certificate for %s expires within threshold (%v <= %v), triggering renewal", domain, timeUntilExpiry, renewalThreshold)

		// Trigger certificate renewal by making a fake TLS handshake
		hello := &tls.ClientHelloInfo{
			ServerName: domain,
		}

		// Use singleflight so concurrent renewals for the same domain are coalesced.
		log.Printf("[autocert] Renewal: obtaining certificate for %s", domain)
		cert, err := am.manager.GetCertificate(hello)
		if err != nil {
			log.Printf("[autocert] manager.GetCertificate returned error for %s: %v", domain, err)
		} else {
			log.Printf("[autocert] manager.GetCertificate returned certificate for %s: certlen=%d", domain, len(cert.Certificate))
		}
		if err != nil {
			log.Printf("[autocert] Failed to renew certificate for %s: %v", domain, err)
		} else {
			log.Printf("[autocert] Successfully renewed certificate for %s", domain)
		}
	} else {
		log.Printf("[autocert] Certificate for %s is not due for renewal (timeUntilExpiry=%v > threshold=%v)", domain, timeUntilExpiry, renewalThreshold)
	}
}

// GetCertificateInfo returns information about certificates for all configured domains.
func (am *AutocertManager) GetCertificateInfo(ctx context.Context) ([]CertificateInfo, error) {
	var infos []CertificateInfo

	for _, domain := range am.config.Domains {
		info, err := am.getDomainCertificateInfo(ctx, domain)
		if err != nil {
			log.Printf("[autocert] Failed to get certificate info for %s: %v", domain, err)
			infos = append(infos, CertificateInfo{
				Domain: domain,
				Status: "error",
				Error:  err.Error(),
			})
			continue
		}
		infos = append(infos, info)
	}

	return infos, nil
}

// getDomainCertificateInfo gets certificate information for a single domain.
func (am *AutocertManager) getDomainCertificateInfo(ctx context.Context, domain string) (CertificateInfo, error) {
	// Use manager.GetCertificate (via singleflight) to obtain the authoritative
	// certificate rather than probing the cache by key. This avoids false
	// "not_found" results caused by autocert's transient token files.
	// Obtain certificate directly from manager
	hello := &tls.ClientHelloInfo{ServerName: domain}
	tlsCert, err := am.manager.GetCertificate(hello)
	if err != nil {
		return CertificateInfo{
			Domain: domain,
			Status: "not_found",
			Error:  err.Error(),
		}, nil
	}

	if tlsCert == nil || len(tlsCert.Certificate) == 0 {
		return CertificateInfo{}, fmt.Errorf("empty or missing certificate for %s", domain)
	}

	if len(tlsCert.Certificate) == 0 {
		return CertificateInfo{}, fmt.Errorf("empty certificate chain")
	}

	// Parse first certificate for expiry info
	cert0, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return CertificateInfo{}, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	expiresAt := cert0.NotAfter
	daysToExpiry := int(time.Until(expiresAt).Hours() / 24)

	status := "valid"
	if daysToExpiry <= 0 {
		status = "expired"
	} else if daysToExpiry <= am.config.RenewalThreshold {
		status = "expiring_soon"
	}

	return CertificateInfo{
		Domain:       domain,
		Status:       status,
		ExpiresAt:    expiresAt,
		DaysToExpiry: daysToExpiry,
		Issuer:       tlsCert.Leaf.Issuer.String(),
		SerialNumber: tlsCert.Leaf.SerialNumber.String(),
	}, nil
}

// CertificateInfo contains information about a certificate.
type CertificateInfo struct {
	Domain       string    `json:"domain"`
	Status       string    `json:"status"` // "valid", "expiring_soon", "expired", "not_found", "error"
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	DaysToExpiry int       `json:"days_to_expiry,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// HealthCheck performs a health check on the autocert manager.
func (am *AutocertManager) HealthCheck(ctx context.Context) error {
	// Check if cache directory is accessible
	if _, err := os.Stat(am.config.CacheDir); err != nil {
		return fmt.Errorf("cache directory not accessible: %w", err)
	}

	// Check if we can reach the ACME server
	client := am.manager.Client
	if client == nil {
		return fmt.Errorf("ACME client not configured")
	}

	// Try to get directory information from ACME server
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := client.Discover(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to ACME server: %w", err)
	}

	return nil
}

// Close cleans up resources used by the autocert manager.
func (am *AutocertManager) Close() error {
	// Currently no cleanup needed, but this method is provided for future use
	log.Printf("[autocert] Autocert manager closed")
	return nil
}
