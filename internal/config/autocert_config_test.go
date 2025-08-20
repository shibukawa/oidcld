package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestAutocertConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "disabled autocert should pass validation",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled: false,
				},
			},
			expectError: false,
		},
		{
			name: "nil autocert should pass validation",
			config: &Config{
				Autocert: nil,
			},
			expectError: false,
		},
		{
			name: "valid production autocert config",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:          true,
					Domains:          []string{"auth.example.com"},
					Email:            "admin@example.com",
					AgreeTOS:         true,
					ACMEServer:       "https://acme-v02.api.letsencrypt.org/directory",
					CacheDir:         "./autocert-cache",
					RenewalThreshold: 30,
				},
			},
			expectError: false,
		},
		{
			name: "valid staging autocert config",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:          true,
					Domains:          []string{"auth-staging.example.com"},
					Email:            "staging@example.com",
					AgreeTOS:         true,
					Staging:          true,
					RenewalThreshold: 7,
				},
			},
			expectError: false,
		},
		{
			name: "valid local autocert config",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:  true,
					Domains:  []string{"auth.local.dev"},
					Email:    "dev@example.com",
					AgreeTOS: true,
				},
			},
			expectError: false,
		},
		{
			name: "missing domains should fail",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:  true,
					Email:    "admin@example.com",
					AgreeTOS: true,
				},
			},
			expectError: true,
			errorMsg:    "autocert.domains is required when autocert is enabled",
		},
		{
			name: "empty domains should fail",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:  true,
					Domains:  []string{},
					Email:    "admin@example.com",
					AgreeTOS: true,
				},
			},
			expectError: true,
			errorMsg:    "autocert.domains is required when autocert is enabled",
		},
		{
			name: "missing email should fail",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:  true,
					Domains:  []string{"auth.example.com"},
					AgreeTOS: true,
				},
			},
			expectError: true,
			errorMsg:    "autocert.email is required when autocert is enabled",
		},
		{
			name: "missing agree_tos should fail",
			config: &Config{
				Autocert: &AutocertConfig{
					Enabled:  true,
					Domains:  []string{"auth.example.com"},
					Email:    "admin@example.com",
					AgreeTOS: false,
				},
			},
			expectError: true,
			errorMsg:    "autocert.agree_tos must be true when autocert is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateAutocertConfig()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if err.Error() != tt.errorMsg {
					t.Errorf("expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAutocertConfig_DefaultValues(t *testing.T) {
	config := &Config{
		Autocert: &AutocertConfig{
			Enabled:  true,
			Domains:  []string{"auth.example.com"},
			Email:    "admin@example.com",
			AgreeTOS: true,
			// Leave other fields empty to test defaults
		},
	}

	err := config.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	autocert := config.Autocert

	// Test default values are set
	if autocert.ACMEServer != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("expected default ACME server, got %s", autocert.ACMEServer)
	}

	if autocert.CacheDir != "./autocert-cache" {
		t.Errorf("expected default cache dir, got %s", autocert.CacheDir)
	}

	if autocert.RenewalThreshold != 30 {
		t.Errorf("expected default renewal threshold 30, got %d", autocert.RenewalThreshold)
	}
}

func TestAutocertConfig_StagingDefaults(t *testing.T) {
	config := &Config{
		Autocert: &AutocertConfig{
			Enabled:  true,
			Domains:  []string{"auth-staging.example.com"},
			Email:    "staging@example.com",
			AgreeTOS: true,
			Staging:  true,
			// ACMEServer should be set to staging
		},
	}

	err := config.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	expectedStagingServer := "https://acme-staging-v02.api.letsencrypt.org/directory"
	if config.Autocert.ACMEServer != expectedStagingServer {
		t.Errorf("expected staging ACME server %s, got %s", expectedStagingServer, config.Autocert.ACMEServer)
	}
}

func TestAutocertConfig_ChallengeDefaults(t *testing.T) {
	config := &Config{
		Autocert: &AutocertConfig{
			Enabled:   true,
			Domains:   []string{"auth.example.com"},
			Email:     "admin@example.com",
			AgreeTOS:  true,
			Challenge: &AutocertChallengeConfig{
				// Leave fields empty to test defaults
			},
		},
	}

	err := config.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	challenge := config.Autocert.Challenge
	if challenge.Port != 80 {
		t.Errorf("expected default challenge port 80, got %d", challenge.Port)
	}

	if challenge.Timeout != "30s" {
		t.Errorf("expected default challenge timeout 30s, got %s", challenge.Timeout)
	}
}

func TestAutocertConfig_RateLimitDefaults(t *testing.T) {
	config := &Config{
		Autocert: &AutocertConfig{
			Enabled:   true,
			Domains:   []string{"auth.example.com"},
			Email:     "admin@example.com",
			AgreeTOS:  true,
			RateLimit: &AutocertRateLimitConfig{
				// Leave fields empty to test defaults
			},
		},
	}

	err := config.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	rateLimit := config.Autocert.RateLimit
	if rateLimit.RequestsPerSecond != 10 {
		t.Errorf("expected default requests per second 10, got %d", rateLimit.RequestsPerSecond)
	}

	if rateLimit.Burst != 20 {
		t.Errorf("expected default burst 20, got %d", rateLimit.Burst)
	}
}

func TestAutocertConfig_RetryDefaults(t *testing.T) {
	config := &Config{
		Autocert: &AutocertConfig{
			Enabled:  true,
			Domains:  []string{"auth.example.com"},
			Email:    "admin@example.com",
			AgreeTOS: true,
			Retry:    &AutocertRetryConfig{
				// Leave fields empty to test defaults
			},
		},
	}

	err := config.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	retry := config.Autocert.Retry
	if retry.MaxAttempts != 3 {
		t.Errorf("expected default max attempts 3, got %d", retry.MaxAttempts)
	}

	if retry.InitialDelay != "1s" {
		t.Errorf("expected default initial delay 1s, got %s", retry.InitialDelay)
	}

	if retry.MaxDelay != "30s" {
		t.Errorf("expected default max delay 30s, got %s", retry.MaxDelay)
	}
}

func TestGetAutocertDefaults(t *testing.T) {
	defaults := GetAutocertDefaults()

	if defaults.Enabled {
		t.Error("expected autocert to be disabled by default")
	}

	if defaults.ACMEServer != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("expected default ACME server, got %s", defaults.ACMEServer)
	}

	if defaults.CacheDir != "./autocert-cache" {
		t.Errorf("expected default cache dir, got %s", defaults.CacheDir)
	}

	if defaults.RenewalThreshold != 30 {
		t.Errorf("expected default renewal threshold 30, got %d", defaults.RenewalThreshold)
	}

	if defaults.AgreeTOS {
		t.Error("expected agree_tos to be false by default")
	}

	if defaults.Staging {
		t.Error("expected staging to be false by default")
	}

	// Test nested defaults
	if defaults.Challenge == nil {
		t.Fatal("expected challenge config to be set")
	}
	if defaults.Challenge.Port != 80 {
		t.Errorf("expected default challenge port 80, got %d", defaults.Challenge.Port)
	}

	if defaults.RateLimit == nil {
		t.Fatal("expected rate limit config to be set")
	}
	if defaults.RateLimit.RequestsPerSecond != 10 {
		t.Errorf("expected default requests per second 10, got %d", defaults.RateLimit.RequestsPerSecond)
	}

	if defaults.Retry == nil {
		t.Fatal("expected retry config to be set")
	}
	if defaults.Retry.MaxAttempts != 3 {
		t.Errorf("expected default max attempts 3, got %d", defaults.Retry.MaxAttempts)
	}
}

func TestAutocertConfig_YAMLSerialization(t *testing.T) {
	// Test YAML marshaling and unmarshaling
	originalConfig := &Config{
		OIDCLD: OIDCLDConfig{
			Issuer: "https://auth.example.com",
		},
		Autocert: &AutocertConfig{
			Enabled:          true,
			ACMEServer:       "https://acme-v02.api.letsencrypt.org/directory",
			Domains:          []string{"auth.example.com", "api.example.com"},
			CacheDir:         "./autocert-cache",
			RenewalThreshold: 30,
			Email:            "admin@example.com",
			AgreeTOS:         true,
			Staging:          false,
			Challenge: &AutocertChallengeConfig{
				Port:    80,
				Timeout: "30s",
			},
			RateLimit: &AutocertRateLimitConfig{
				RequestsPerSecond: 10,
				Burst:             20,
			},
			Retry: &AutocertRetryConfig{
				MaxAttempts:  3,
				InitialDelay: "1s",
				MaxDelay:     "30s",
			},
		},
		Users: map[string]User{
			"admin": {
				DisplayName: "Administrator",
				ExtraClaims: map[string]any{
					"email": "admin@example.com",
				},
			},
		},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("failed to marshal config to YAML: %v", err)
	}

	// Unmarshal from YAML
	var unmarshaledConfig Config
	err = yaml.Unmarshal(yamlData, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("failed to unmarshal config from YAML: %v", err)
	}

	// Validate the unmarshaled config
	err = unmarshaledConfig.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed for unmarshaled config: %v", err)
	}

	// Check key fields
	if unmarshaledConfig.Autocert.Enabled != originalConfig.Autocert.Enabled {
		t.Error("autocert enabled field mismatch")
	}

	if len(unmarshaledConfig.Autocert.Domains) != len(originalConfig.Autocert.Domains) {
		t.Error("autocert domains length mismatch")
	}

	if unmarshaledConfig.Autocert.Email != originalConfig.Autocert.Email {
		t.Error("autocert email field mismatch")
	}
}

func TestAutocertConfig_FileOperations(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-autocert.yaml")

	// Create test configuration
	config := &Config{
		OIDCLD: OIDCLDConfig{
			Issuer: "https://auth.example.com",
		},
		Autocert: &AutocertConfig{
			Enabled:          true,
			Domains:          []string{"auth.example.com"},
			Email:            "admin@example.com",
			AgreeTOS:         true,
			CacheDir:         "./autocert-cache",
			RenewalThreshold: 30,
		},
		Users: map[string]User{
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	// Marshal and save to file
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	err = os.WriteFile(configPath, yamlData, 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Load configuration from file
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Validate loaded configuration
	err = loadedConfig.ValidateAutocertConfig()
	if err != nil {
		t.Fatalf("validation failed for loaded config: %v", err)
	}

	// Verify autocert configuration was loaded correctly
	if loadedConfig.Autocert == nil {
		t.Fatal("autocert config was not loaded")
	}

	if !loadedConfig.Autocert.Enabled {
		t.Error("autocert should be enabled")
	}

	if len(loadedConfig.Autocert.Domains) != 1 || loadedConfig.Autocert.Domains[0] != "auth.example.com" {
		t.Error("autocert domains not loaded correctly")
	}

	if loadedConfig.Autocert.Email != "admin@example.com" {
		t.Error("autocert email not loaded correctly")
	}
}
