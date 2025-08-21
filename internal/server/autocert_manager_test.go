package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
)

func TestNewAutocertManager(t *testing.T) {
	logger := NewLogger()

	tests := []struct {
		name        string
		config      *config.AutocertConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config should fail",
			config:      nil,
			expectError: true,
			errorMsg:    "autocert is not enabled",
		},
		{
			name: "disabled config should fail",
			config: &config.AutocertConfig{
				Enabled: false,
			},
			expectError: true,
			errorMsg:    "autocert is not enabled",
		},
		{
			name: "invalid config should fail",
			config: &config.AutocertConfig{
				Enabled: true,
				// Missing required fields
			},
			expectError: true,
			errorMsg:    "invalid autocert configuration",
		},
		{
			name: "valid production config should succeed",
			config: &config.AutocertConfig{
				Enabled:          true,
				Domains:          []string{"auth.example.com"},
				Email:            "admin@example.com",
				AgreeTOS:         true,
				ACMEServer:       "https://acme-v02.api.letsencrypt.org/directory",
				CacheDir:         filepath.Join(t.TempDir(), "autocert-cache"),
				RenewalThreshold: 1,
			},
			expectError: false,
		},
		{
			name: "valid staging config should succeed",
			config: &config.AutocertConfig{
				Enabled:          true,
				Domains:          []string{"auth-staging.example.com"},
				Email:            "staging@example.com",
				AgreeTOS:         true,
				Staging:          true,
				CacheDir:         filepath.Join(t.TempDir(), "autocert-cache"),
				RenewalThreshold: 7,
			},
			expectError: false,
		},
		{
			name: "valid local config should succeed",
			config: &config.AutocertConfig{
				Enabled:          true,
				Domains:          []string{"auth.local.dev"},
				Email:            "dev@example.com",
				AgreeTOS:         true,
				CacheDir:         filepath.Join(t.TempDir(), "autocert-cache"),
				RenewalThreshold: 7,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewAutocertManager(tt.config, logger)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error()[:len(tt.errorMsg)] != tt.errorMsg {
					t.Errorf("expected error message to start with %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if manager == nil {
					t.Error("expected manager to be created")
					return
				}

				// Verify manager configuration
				if manager.config != tt.config {
					t.Error("manager config not set correctly")
				}

				if manager.manager == nil {
					t.Error("autocert.Manager not created")
				}

				// logger field removed from AutocertManager; no assertion here

				// Verify cache directory was created
				if _, err := os.Stat(tt.config.CacheDir); os.IsNotExist(err) {
					t.Errorf("cache directory %s was not created", tt.config.CacheDir)
				}
			}
		})
	}
}

func TestAutocertManager_GetTLSConfig(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.example.com"},
		Email:            "admin@example.com",
		AgreeTOS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 1,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	tlsConfig := manager.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatal("TLS config is nil")
	}

	// Verify TLS config has GetCertificate function
	if tlsConfig.GetCertificate == nil {
		t.Error("TLS config GetCertificate function is nil")
	}

	// Verify NextProtos includes h2 for HTTP/2 support
	found := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("TLS config should include h2 in NextProtos for HTTP/2 support")
	}
}

func TestAutocertManager_HTTPHandler(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.example.com"},
		Email:            "admin@example.com",
		AgreeTOS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Create a simple fallback handler
	fallback := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("fallback"))
	}

	handler := manager.HTTPHandler(http.HandlerFunc(fallback))
	if handler == nil {
		t.Fatal("HTTP handler is nil")
	}

	// Test that handler is created (we can't easily test ACME challenge handling without a real ACME server)
	// This test mainly verifies the handler is properly wrapped
}

func TestAutocertManager_CertificateInfo(t *testing.T) {
	// CertificateInfo helpers removed; no test here.
}

func TestAutocertManager_HealthCheck(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		config      *config.AutocertConfig
		expectError bool
	}{
		{
			name: "valid config should pass health check",
			config: &config.AutocertConfig{
				Enabled:          true,
				Domains:          []string{"auth.example.com"},
				Email:            "admin@example.com",
				AgreeTOS:         true,
				CacheDir:         filepath.Join(tempDir, "valid-cache"),
				RenewalThreshold: 30,
			},
			expectError: false,
		},
		{
			name: "inaccessible cache directory should fail",
			config: &config.AutocertConfig{
				Enabled:          true,
				Domains:          []string{"auth.example.com"},
				Email:            "admin@example.com",
				AgreeTOS:         true,
				CacheDir:         "/root/invalid-cache", // Use a path that definitely won't be accessible
				RenewalThreshold: 30,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewAutocertManager(tt.config, logger)

			if tt.expectError {
				// For invalid cache directory, expect error during manager creation
				if tt.config.CacheDir == "/root/invalid-cache" {
					if err == nil {
						t.Error("expected error during manager creation for invalid cache directory")
					}
					return // Skip health check test since manager creation failed
				}
			}

			if err != nil {
				t.Fatalf("failed to create autocert manager: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = manager.HealthCheck(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("expected health check to fail but it passed")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected health check error: %v", err)
				}
			}
		})
	}
}

func TestAutocertManager_RenewalMonitor(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.example.com"},
		Email:            "admin@example.com",
		AgreeTOS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Instead of starting a background renewal monitor (removed), verify that
	// the underlying autocert.Manager has RenewBefore configured based on
	// the config's RenewalThreshold.

	expected := time.Duration(config.RenewalThreshold) * 24 * time.Hour
	if manager.manager == nil {
		t.Fatal("autocert.Manager is nil")
	}

	if manager.manager.RenewBefore != expected {
		t.Errorf("expected RenewBefore=%v, got %v", expected, manager.manager.RenewBefore)
	}
}

func TestAutocertManager_LocalConfiguration(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	// Since "local mode" concept was removed, simulate a local ACME setup by
	// providing a custom ACME server URL and enabling InsecureSkipVerify.
	config := &config.AutocertConfig{
		Enabled:            true,
		Domains:            []string{"auth.local.dev"},
		Email:              "dev@example.com",
		AgreeTOS:           true,
		CacheDir:           filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold:   7,
		ACMEServer:         "http://localhost:14000",
		InsecureSkipVerify: true,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Verify ACME client and settings
	if manager.manager.Client == nil {
		t.Fatal("ACME client not configured")
	}

	if manager.manager.Client.DirectoryURL != config.ACMEServer {
		t.Errorf("expected ACME server URL %s, got %s",
			config.ACMEServer, manager.manager.Client.DirectoryURL)
	}

	// When InsecureSkipVerify is requested, the underlying HTTPClient should be
	// configured accordingly.
	if !config.InsecureSkipVerify {
		return
	}

	if manager.manager.Client.HTTPClient == nil {
		t.Fatal("HTTP client not configured for ACME server")
	}

	transport, ok := manager.manager.Client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("HTTP transport not configured correctly")
	}

	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not configured on HTTP client")
	}
}

func TestAutocertManager_StagingConfiguration(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth-staging.example.com"},
		Email:            "staging@example.com",
		AgreeTOS:         true,
		Staging:          true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 7,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Verify staging ACME server is configured
	expectedStagingURL := "https://acme-staging-v02.api.letsencrypt.org/directory"
	if manager.manager.Client.DirectoryURL != expectedStagingURL {
		t.Errorf("expected staging ACME server URL %s, got %s",
			expectedStagingURL, manager.manager.Client.DirectoryURL)
	}
}

func TestAutocertManager_ProductionConfiguration(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.example.com"},
		Email:            "admin@example.com",
		AgreeTOS:         true,
		Staging:          false,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Verify production ACME server is configured
	expectedProductionURL := "https://acme-v02.api.letsencrypt.org/directory"
	if manager.manager.Client.DirectoryURL != expectedProductionURL {
		t.Errorf("expected production ACME server URL %s, got %s",
			expectedProductionURL, manager.manager.Client.DirectoryURL)
	}
}

func TestAutocertManager_Close(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.example.com"},
		Email:            "admin@example.com",
		AgreeTOS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Test that Close() doesn't return an error
	err = manager.Close()
	if err != nil {
		t.Errorf("unexpected error from Close(): %v", err)
	}
}

func TestCertificateInfo_Structure(t *testing.T) {
	// CertificateInfo type removed; no structure test needed
}
