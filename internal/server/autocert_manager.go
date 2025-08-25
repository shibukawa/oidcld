package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/shibukawa/oidcld/internal/config"
)

// (No local transport or cache logging: let autocert manage caching and HTTP)

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
		Cache:      dirCache,
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

	// For test/development containers we don't ship a root CA, so default to
	// skipping TLS verification for ACME HTTP requests. This makes local ACME
	// servers (e.g., Pebble) reachable without requiring root certs inside the
	// container. We still keep the config flag present for compatibility but
	// default to insecure behavior.
	// Set up ACME HTTP client (insecure for test environments by default).
	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	manager.Client.HTTPClient = &http.Client{Transport: baseTransport}

	am := &AutocertManager{
		config:  cfg,
		manager: manager,
		logger:  logger,
	}

	// Configure autocert.Manager's RenewBefore so autocert handles renewals.
	// RenewBefore is a duration before expiry when manager will attempt to renew.
	if cfg.RenewalThreshold > 0 {
		manager.RenewBefore = time.Duration(cfg.RenewalThreshold) * 24 * time.Hour
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
	return am.manager.GetCertificate(hello)
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
			// intentionally silent
			return ctx.Err()
		default:
		}

		// intentionally silent

		// Rely on manager.GetCertificate which will consult the cache internally.

		hello := &tls.ClientHelloInfo{ServerName: domain}
		_, err := am.manager.GetCertificate(hello)
		if err != nil {
			return err
		}

		// Small pause between domains to avoid hammering ACME server
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

// (Certificate info helpers removed — not used in production code path)

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
		// If configured to skip TLS verification for ACME (local test servers),
		// retry once with an HTTP client that disables TLS verification. This
		// helps when the ACME server uses a self-signed or locally-trusted cert.
		if am.config.InsecureSkipVerify {
			// intentionally silent
			retryClient := *client // shallow copy
			retryClient.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			_, err2 := retryClient.Discover(ctx)
			if err2 == nil {
				return nil
			}
			return fmt.Errorf("failed to connect to ACME server (retry with insecure): %v; original: %w", err2, err)
		}
		return fmt.Errorf("failed to connect to ACME server: %w", err)
	}

	return nil
}

// Close cleans up resources used by the autocert manager.
func (am *AutocertManager) Close() error {
	// Currently no cleanup needed, but this method is provided for future use
	return nil
}
