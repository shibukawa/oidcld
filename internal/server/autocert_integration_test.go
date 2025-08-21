package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
)

// createAutocertTestServer creates a server for testing with proper arguments
func createAutocertTestServer(cfg *config.Config) (*Server, error) {
	// Generate test private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create slog logger
	slogLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce log noise in tests
	}))

	return NewServer(cfg, privateKey, slogLogger)
}

func TestServer_AutocertIntegration(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Create configuration with autocert enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.example.com",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 1,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server with autocert configuration
	server, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Verify server was created successfully
	if server == nil {
		t.Fatal("server is nil")
	}

	// Test that server has autocert configuration
	if server.config.Autocert == nil {
		t.Fatal("server autocert config is nil")
	}

	if !server.config.Autocert.Enabled {
		t.Error("autocert should be enabled")
	}

	// Test autocert manager creation
	autocertManager, err := NewAutocertManager(cfg.Autocert, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	if autocertManager == nil {
		t.Fatal("autocert manager is nil")
	}
}

func TestServer_AutocertTLSConfig(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Create configuration with autocert enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.example.com",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 30,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server
	_, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create autocert manager
	autocertManager, err := NewAutocertManager(cfg.Autocert, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Test TLS config creation
	tlsConfig := autocertManager.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatal("TLS config is nil")
	}

	// Verify TLS config has required fields
	if tlsConfig.GetCertificate == nil {
		t.Error("TLS config GetCertificate function is nil")
	}

	// Test that NextProtos includes HTTP/2
	foundH2 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h2" {
			foundH2 = true
			break
		}
	}
	if !foundH2 {
		t.Error("TLS config should include h2 in NextProtos")
	}
}

func TestServer_AutocertHTTPHandler(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Create configuration with autocert enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.example.com",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 30,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server
	server, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create autocert manager
	autocertManager, err := NewAutocertManager(cfg.Autocert, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Test HTTP handler creation
	handler := autocertManager.HTTPHandler(server.Handler())
	if handler == nil {
		t.Fatal("HTTP handler is nil")
	}

	// The handler should wrap the server's main handler
	// We can't easily test ACME challenge handling without a real ACME server,
	// but we can verify the handler is properly created
}

func TestServer_AutocertDisabled(t *testing.T) {
	// Create configuration with autocert disabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "http://localhost:18888",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		// No autocert configuration (disabled by default)
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server without autocert
	server, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Verify server was created successfully
	if server == nil {
		t.Fatal("server is nil")
	}

	// Test that autocert is not configured
	if server.config.Autocert != nil && server.config.Autocert.Enabled {
		t.Error("autocert should not be enabled")
	}
}

func TestServer_AutocertLocalConfiguration(t *testing.T) {
	tempDir := t.TempDir()

	// Create configuration with local autocert enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.local.dev",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.local.dev"},
			Email:            "dev@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 7,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server with local autocert configuration
	server, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Verify server was created successfully
	if server == nil {
		t.Fatal("server is nil")
	}

	// Test that local autocert is configured
	if server.config.Autocert == nil {
		t.Fatal("server autocert config is nil")
	}

	if !server.config.Autocert.Enabled {
		t.Error("autocert should be enabled")
	}
}

func TestServer_AutocertHealthCheck(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Create configuration with autocert enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.example.com",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 30,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server
	_, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create autocert manager
	autocertManager, err := NewAutocertManager(cfg.Autocert, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Test health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = autocertManager.HealthCheck(ctx)
	if err != nil {
		t.Errorf("health check failed: %v", err)
	}
}

func TestServer_AutocertCertificateInfo(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Create configuration with multiple domains
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.example.com",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com", "api.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 30,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server
	_, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create autocert manager
	autocertManager, err := NewAutocertManager(cfg.Autocert, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Test certificate info retrieval
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	infos, err := autocertManager.GetCertificateInfo(ctx)
	if err != nil {
		t.Fatalf("failed to get certificate info: %v", err)
	}

	// Should return info for all configured domains
	if len(infos) != len(cfg.Autocert.Domains) {
		t.Errorf("expected %d certificate infos, got %d", len(cfg.Autocert.Domains), len(infos))
	}

	// All certificates should be "not_found" since we haven't obtained any
	for _, info := range infos {
		if info.Status != "not_found" {
			t.Errorf("expected status 'not_found' for %s, got %s", info.Domain, info.Status)
		}

		// Verify domain is in the configured list
		found := false
		for _, domain := range cfg.Autocert.Domains {
			if info.Domain == domain {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected domain in certificate info: %s", info.Domain)
		}
	}
}

func TestServer_AutocertRenewalMonitor(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Create configuration with autocert enabled
	cfg := &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:         "https://auth.example.com",
			ValidAudiences: []string{"test-client"},
			ExpiredIn:      3600,
		},
		Autocert: &config.AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         filepath.Join(tempDir, "autocert-cache"),
			RenewalThreshold: 30,
		},
		Users: map[string]config.User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Create server
	_, err := createAutocertTestServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create autocert manager
	autocertManager, err := NewAutocertManager(cfg.Autocert, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// The renewal monitor was removed; assert RenewBefore is configured.
	expected := time.Duration(cfg.Autocert.RenewalThreshold) * 24 * time.Hour
	if autocertManager.manager == nil {
		t.Fatal("autocert.Manager is nil")
	}
	if autocertManager.manager.RenewBefore != expected {
		t.Errorf("expected RenewBefore=%v, got %v", expected, autocertManager.manager.RenewBefore)
	}
}
