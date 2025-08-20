package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/shibukawa/oidcld/internal/config"
)

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
	manager := &autocert.Manager{
		Cache:      autocert.DirCache(cfg.CacheDir),
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
	cert, err := am.manager.GetCertificate(hello)
	if err != nil {
		am.logger.Error(fmt.Sprintf("Failed to get certificate for %s", hello.ServerName), err)
		return nil, err
	}

	// Log certificate acquisition success with compact format
	if cert.Leaf != nil {
		color.Green("🔐 Certificate obtained: %s (expires: %s)", hello.ServerName, cert.Leaf.NotAfter.Format("2006-01-02 15:04:05"))
	} else {
		color.Green("🔐 Certificate obtained: %s", hello.ServerName)
	}
	return cert, nil
}

// StartRenewalMonitor starts a background goroutine that monitors certificate expiration
// and triggers renewal when certificates are close to expiring.
func (am *AutocertManager) StartRenewalMonitor(ctx context.Context) {
	go am.renewalMonitor(ctx)
}

// renewalMonitor runs in the background and checks for certificates that need renewal.
func (am *AutocertManager) renewalMonitor(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	am.logger.Info("Started certificate renewal monitor (checking every 24 hours)")

	for {
		select {
		case <-ctx.Done():
			am.logger.Info("Certificate renewal monitor stopped")
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
		am.checkDomainCertificate(ctx, domain)
	}
}

// checkDomainCertificate checks a single domain's certificate and renews if necessary.
func (am *AutocertManager) checkDomainCertificate(ctx context.Context, domain string) {
	// Get the current certificate from cache
	cert, err := am.manager.Cache.Get(ctx, domain)
	if err != nil {
		am.logger.Warning(fmt.Sprintf("No cached certificate found for %s, will obtain on next request: %v", domain, err))
		return
	}

	// Parse the certificate to check expiration
	tlsCert, err := tls.X509KeyPair(cert, cert)
	if err != nil {
		am.logger.Error(fmt.Sprintf("Failed to parse certificate for %s", domain), err)
		return
	}

	if len(tlsCert.Certificate) == 0 {
		am.logger.Error(fmt.Sprintf("Empty certificate chain for %s", domain), fmt.Errorf("empty certificate chain"))
		return
	}

	// Check if certificate needs renewal
	renewalThreshold := time.Duration(am.config.RenewalThreshold) * 24 * time.Hour
	expiresAt := tlsCert.Leaf.NotAfter
	timeUntilExpiry := time.Until(expiresAt)

	if timeUntilExpiry <= renewalThreshold {
		am.logger.Info(fmt.Sprintf("Certificate for %s expires in %v, triggering renewal", domain, timeUntilExpiry))

		// Trigger certificate renewal by making a fake TLS handshake
		hello := &tls.ClientHelloInfo{
			ServerName: domain,
		}

		_, err := am.manager.GetCertificate(hello)
		if err != nil {
			am.logger.Error(fmt.Sprintf("Failed to renew certificate for %s", domain), err)
		} else {
			am.logger.Info(fmt.Sprintf("Successfully renewed certificate for %s", domain))
		}
	} else {
		// Use Info instead of Debug since Debug is not available
		am.logger.Info(fmt.Sprintf("Certificate for %s is valid for %v more", domain, timeUntilExpiry))
	}
}

// GetCertificateInfo returns information about certificates for all configured domains.
func (am *AutocertManager) GetCertificateInfo(ctx context.Context) ([]CertificateInfo, error) {
	var infos []CertificateInfo

	for _, domain := range am.config.Domains {
		info, err := am.getDomainCertificateInfo(ctx, domain)
		if err != nil {
			am.logger.Warning(fmt.Sprintf("Failed to get certificate info for %s: %v", domain, err))
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
	// Try to get certificate from cache
	cert, err := am.manager.Cache.Get(ctx, domain)
	if err != nil {
		return CertificateInfo{
			Domain: domain,
			Status: "not_found",
			Error:  err.Error(),
		}, nil
	}

	// Parse certificate
	tlsCert, err := tls.X509KeyPair(cert, cert)
	if err != nil {
		return CertificateInfo{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if len(tlsCert.Certificate) == 0 {
		return CertificateInfo{}, fmt.Errorf("empty certificate chain")
	}

	expiresAt := tlsCert.Leaf.NotAfter
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
	am.logger.Info("Autocert manager closed")
	return nil
}
