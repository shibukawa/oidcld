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
				AgreeToS:         true,
				ACMEServer:       "https://acme-v02.api.letsencrypt.org/directory",
				CacheDir:         filepath.Join(t.TempDir(), "autocert-cache"),
				RenewalThreshold: 30,
			},
			expectError: false,
		},
		{
			name: "valid staging config should succeed",
			config: &config.AutocertConfig{
				Enabled:          true,
				Domains:          []string{"auth-staging.example.com"},
				Email:            "staging@example.com",
				AgreeToS:         true,
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
				AgreeToS:         true,
				CacheDir:         filepath.Join(t.TempDir(), "autocert-cache"),
				RenewalThreshold: 7,
				Local: &config.AutocertLocalConfig{
					Enabled:            true,
					ACMEServer:         "https://localhost:14000/dir",
					InsecureSkipVerify: true,
				},
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

				if manager.logger != logger {
					t.Error("logger not set correctly")
				}

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
		AgreeToS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
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
		AgreeToS:         true,
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
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.example.com", "api.example.com"},
		Email:            "admin@example.com",
		AgreeToS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	ctx := context.Background()
	infos, err := manager.GetCertificateInfo(ctx)
	if err != nil {
		t.Fatalf("failed to get certificate info: %v", err)
	}

	// Should return info for all configured domains
	if len(infos) != len(config.Domains) {
		t.Errorf("expected %d certificate infos, got %d", len(config.Domains), len(infos))
	}

	// All certificates should be "not_found" since we haven't obtained any
	for _, info := range infos {
		if info.Status != "not_found" {
			t.Errorf("expected status 'not_found' for %s, got %s", info.Domain, info.Status)
		}

		// Verify domain is in the configured list
		found := false
		for _, domain := range config.Domains {
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
				AgreeToS:         true,
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
				AgreeToS:         true,
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
		AgreeToS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 30,
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Test that renewal monitor can be started and stopped
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start renewal monitor
	manager.StartRenewalMonitor(ctx)

	// Wait for context to be cancelled
	<-ctx.Done()

	// Test passes if no panic occurs and monitor stops gracefully
}

func TestAutocertManager_LocalConfiguration(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth.local.dev"},
		Email:            "dev@example.com",
		AgreeToS:         true,
		CacheDir:         filepath.Join(tempDir, "autocert-cache"),
		RenewalThreshold: 7,
		Local: &config.AutocertLocalConfig{
			Enabled:            true,
			ACMEServer:         "https://localhost:14000/dir",
			InsecureSkipVerify: true,
		},
	}

	manager, err := NewAutocertManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create autocert manager: %v", err)
	}

	// Verify local ACME server configuration
	if manager.manager.Client == nil {
		t.Fatal("ACME client not configured")
	}

	if manager.manager.Client.DirectoryURL != config.Local.ACMEServer {
		t.Errorf("expected ACME server URL %s, got %s",
			config.Local.ACMEServer, manager.manager.Client.DirectoryURL)
	}

	// Verify insecure skip verify is configured
	if manager.manager.Client.HTTPClient == nil {
		t.Fatal("HTTP client not configured for local ACME server")
	}

	transport, ok := manager.manager.Client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("HTTP transport not configured correctly")
	}

	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not configured for local ACME server")
	}
}

func TestAutocertManager_StagingConfiguration(t *testing.T) {
	logger := NewLogger()
	tempDir := t.TempDir()

	config := &config.AutocertConfig{
		Enabled:          true,
		Domains:          []string{"auth-staging.example.com"},
		Email:            "staging@example.com",
		AgreeToS:         true,
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
		AgreeToS:         true,
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
		AgreeToS:         true,
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
	// Test that CertificateInfo struct has expected fields
	info := CertificateInfo{
		Domain:       "auth.example.com",
		Status:       "valid",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
		DaysToExpiry: 30,
		Issuer:       "Let's Encrypt Authority X3",
		SerialNumber: "123456789",
		Error:        "",
	}

	if info.Domain != "auth.example.com" {
		t.Error("Domain field not set correctly")
	}

	if info.Status != "valid" {
		t.Error("Status field not set correctly")
	}

	if info.DaysToExpiry != 30 {
		t.Error("DaysToExpiry field not set correctly")
	}

	if info.Issuer != "Let's Encrypt Authority X3" {
		t.Error("Issuer field not set correctly")
	}

	if info.SerialNumber != "123456789" {
		t.Error("SerialNumber field not set correctly")
	}
}
