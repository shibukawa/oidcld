// Package config provides functionality to manage OIDCLD configuration
package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/goccy/go-yaml"
)

// Static errors for better error handling.
var (
	ErrNoUsersConfigured    = errors.New("no users configured")
	ErrUserNotFound         = errors.New("user not found")
	ErrUnknownConfigKey     = errors.New("unknown configuration key")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)

// Config represents the OIDCLD configuration.
type Config struct {
	OIDCLD   OIDCLDConfig    `yaml:"oidcld"`
	EntraID  *EntraIDConfig  `yaml:"entraid,omitempty"`
	CORS     *CORSConfig     `yaml:"cors,omitempty"`
	Autocert *AutocertConfig `yaml:"autocert,omitempty"`
	Users    map[string]User `yaml:"users"`
}

// OIDCLDConfig represents the core OpenID Connect configuration.
type OIDCLDConfig struct {
	Issuer                    string   `yaml:"iss,omitempty"`
	ValidAudiences            []string `yaml:"valid_audiences,omitempty"`
	PKCERequired              bool     `yaml:"pkce_required,omitempty"`
	NonceRequired             bool     `yaml:"nonce_required,omitempty"`
	ExpiredIn                 int      `yaml:"expired_in,omitempty"` // Token expiration in seconds
	Algorithm                 string   `yaml:"algorithm,omitempty"`
	ValidScopes               []string `yaml:"valid_scopes,omitempty"`
	PrivateKeyPath            string   `yaml:"private_key_path,omitempty"`
	PublicKeyPath             string   `yaml:"public_key_path,omitempty"`
	RefreshTokenEnabled       bool     `yaml:"refresh_token_enabled,omitempty"`
	RefreshTokenExpiry        int      `yaml:"refresh_token_expiry,omitempty"`
	EndSessionEnabled         bool     `yaml:"end_session_enabled,omitempty"`
	EndSessionEndpointVisible bool     `yaml:"end_session_endpoint_visible,omitempty"`
	VerboseLogging            bool     `yaml:"verbose_logging,omitempty"`
}

// EntraIDConfig represents EntraID/AzureAD compatibility settings.
type EntraIDConfig struct {
	TenantID string `yaml:"tenant_id"`
	Version  string `yaml:"version"`
}

// CORSConfig represents Cross-Origin Resource Sharing configuration.
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled,omitempty"`
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`
	AllowedMethods []string `yaml:"allowed_methods,omitempty"`
	AllowedHeaders []string `yaml:"allowed_headers,omitempty"`
}

// AutocertConfig represents automatic HTTPS certificate configuration.
type AutocertConfig struct {
	Enabled            bool                     `yaml:"enabled,omitempty"`
	Domains            []string                 `yaml:"domains,omitempty"`
	Email              string                   `yaml:"email,omitempty"`
	AgreeTOS           bool                     `yaml:"agree_tos,omitempty"`
	CacheDir           string                   `yaml:"cache_dir,omitempty"`
	ACMEServer         string                   `yaml:"acme_server,omitempty"`
	Staging            bool                     `yaml:"staging,omitempty"`
	RenewalThreshold   int                      `yaml:"renewal_threshold,omitempty"` // Days before expiry to renew
	InsecureSkipVerify bool                     `yaml:"insecure_skip_verify,omitempty"`
	Challenge          *AutocertChallengeConfig `yaml:"challenge,omitempty"`
	RateLimit          *AutocertRateLimitConfig `yaml:"rate_limit,omitempty"`
	Retry              *AutocertRetryConfig     `yaml:"retry,omitempty"`
}

// AutocertChallengeConfig represents ACME challenge configuration.
type AutocertChallengeConfig struct {
	Port    int    `yaml:"port,omitempty"`
	Path    string `yaml:"path,omitempty"`
	Timeout string `yaml:"timeout,omitempty"` // Duration string like "30s"
}

// AutocertRateLimitConfig represents rate limiting configuration for ACME requests.
type AutocertRateLimitConfig struct {
	RequestsPerSecond int `yaml:"requests_per_second,omitempty"`
	Burst             int `yaml:"burst,omitempty"`
}

// AutocertRetryConfig represents retry configuration for ACME requests.
type AutocertRetryConfig struct {
	MaxAttempts  int    `yaml:"max_attempts,omitempty"`
	InitialDelay string `yaml:"initial_delay,omitempty"` // Duration string like "1s"
	MaxDelay     string `yaml:"max_delay,omitempty"`     // Duration string like "30s"
}

// User represents a test user configuration.
type User struct {
	DisplayName      string         `yaml:"display_name"`
	ExtraValidScopes []string       `yaml:"extra_valid_scopes,omitempty"`
	ExtraClaims      map[string]any `yaml:"extra_claims,omitempty"`
}

// Mode represents different configuration initialization modes for the OIDC server.
type Mode string

// Configuration modes for different OIDC server setups.
const (
	ModeStandard  Mode = "standard"
	ModeEntraIDv1 Mode = "entraid-v1"
	ModeEntraIDv2 Mode = "entraid-v2"
)

// LoadConfig loads configuration from a YAML file.
func loadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a YAML file using text template.
func SaveConfig(configPath string, config *Config) error {
	// Resolve the absolute path
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}

	// Ensure the directory exists
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate YAML content using template
	yamlContent, err := generateConfigYAML(config)
	if err != nil {
		return fmt.Errorf("failed to generate config YAML: %w", err)
	}

	// Write to file atomically
	tempFile := absPath + ".tmp"
	if err := os.WriteFile(tempFile, []byte(yamlContent), 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, absPath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// InitializeConfig creates a new configuration file with the specified mode.
func InitializeConfig(configPath string, mode Mode) error {
	config := createDefaultConfig(mode)
	return SaveConfig(configPath, config)
}

// CreateDefaultConfig creates a default configuration based on the mode (exported version).
func CreateDefaultConfig(mode Mode) (*Config, error) {
	return createDefaultConfig(mode), nil
}
func createDefaultConfig(mode Mode) *Config {
	config := &Config{
		OIDCLD: OIDCLDConfig{
			ValidAudiences:            []string{"test-client"},
			PKCERequired:              false,
			NonceRequired:             false,
			ExpiredIn:                 3600,
			ValidScopes:               []string{"admin", "read", "write"},
			RefreshTokenEnabled:       true,
			RefreshTokenExpiry:        86400,
			EndSessionEnabled:         true,
			EndSessionEndpointVisible: true,
		},
		// Add CORS configuration for SPA development - enabled by default for development ease
		CORS: &CORSConfig{
			Enabled: true,
			// Leave origins, methods, and headers empty to use permissive defaults
			// This allows all origins (*), all common HTTP methods, and all common headers
		},
		Users: map[string]User{
			"admin": {
				DisplayName:      "Administrator",
				ExtraValidScopes: []string{"admin", "read", "write"},
				ExtraClaims: map[string]any{
					"email": "admin@example.com",
					"role":  "admin",
				},
			},
			"user": {
				DisplayName:      "Regular User",
				ExtraValidScopes: []string{"read"},
				ExtraClaims: map[string]any{
					"email": "user@example.com",
					"role":  "user",
				},
			},
			"testuser": {
				DisplayName: "Test User",
				ExtraClaims: map[string]any{
					"email": "test@example.com",
				},
			},
		},
	}

	switch mode {
	case ModeStandard:
		config.OIDCLD.Issuer = "http://localhost:18888"
	case ModeEntraIDv1:
		config.OIDCLD.Issuer = "https://login.microsoftonline.com/common"
		config.OIDCLD.NonceRequired = true
		config.EntraID = &EntraIDConfig{
			TenantID: "common",
			Version:  "v1",
		}
	case ModeEntraIDv2:
		config.OIDCLD.Issuer = "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0"
		config.OIDCLD.NonceRequired = true
		config.EntraID = &EntraIDConfig{
			TenantID: "12345678-1234-1234-1234-123456789abc",
			Version:  "v2",
		}
	default:
		config.OIDCLD.Issuer = "http://localhost:18888"
	}

	return config
}

// generateConfigYAML generates YAML configuration using text template
func generateConfigYAML(config *Config) (string, error) {
	tmpl := `# OpenID Connect IdP settings
oidcld:{{if .OIDCLD.Issuer}}
  iss: "{{.OIDCLD.Issuer}}"{{else}}
  # iss: "http://localhost:18888"{{end}}{{if .OIDCLD.ValidAudiences}}
  valid_audiences:{{range .OIDCLD.ValidAudiences}}
    - "{{.}}"{{end}}{{end}}
  pkce_required: {{.OIDCLD.PKCERequired}}
  nonce_required: {{.OIDCLD.NonceRequired}}
  expired_in: {{.OIDCLD.ExpiredIn}}  # Token expiration in seconds{{if .OIDCLD.Algorithm}}
  algorithm: "{{.OIDCLD.Algorithm}}"  # JWT signing algorithm{{else}}
  # algorithm: "RS256"  # Optional, defaults to RS256{{end}}
  # Standard scopes (openid, profile, email) are always included
  valid_scopes:  # Optional custom scopes{{range .OIDCLD.ValidScopes}}
    - "{{.}}"{{end}}{{if .OIDCLD.PrivateKeyPath}}
  private_key_path: "{{.OIDCLD.PrivateKeyPath}}"      # Path to private key file{{else}}
  # private_key_path: ".oidcld.key"      # Optional, generates at runtime if empty{{end}}{{if .OIDCLD.PublicKeyPath}}
  public_key_path: "{{.OIDCLD.PublicKeyPath}}"       # Path to public key file{{else}}
  # public_key_path: ".openidld.pub.key"   # Optional, generates at runtime if empty{{end}}
  refresh_token_enabled: {{.OIDCLD.RefreshTokenEnabled}}             # Enable refresh token support
  refresh_token_expiry: {{.OIDCLD.RefreshTokenExpiry}}             # Refresh token expiry in seconds (24 hours)
  end_session_enabled: {{.OIDCLD.EndSessionEnabled}}               # Enable logout/end session functionality
  end_session_endpoint_visible: {{.OIDCLD.EndSessionEndpointVisible}}      # Show end_session_endpoint in discovery (optional)
{{if .EntraID}}
# EntraID/AzureAD compatibility settings
entraid:
  tenant_id: "{{.EntraID.TenantID}}"
  version: "{{.EntraID.Version}}"
{{end}}{{if .Autocert}}
# Automatic HTTPS certificate configuration
autocert:
  enabled: {{.Autocert.Enabled}}{{if .Autocert.Domains}}
  domains:{{range .Autocert.Domains}}
    - "{{.}}"{{end}}{{end}}{{if .Autocert.Email}}
  email: "{{.Autocert.Email}}"{{end}}
  agree_tos: {{.Autocert.AgreeTOS}}{{if .Autocert.CacheDir}}
  cache_dir: "{{.Autocert.CacheDir}}"{{end}}{{if .Autocert.ACMEServer}}
  acme_server: "{{.Autocert.ACMEServer}}"{{end}}
  staging: {{.Autocert.Staging}}
  renewal_threshold: {{.Autocert.RenewalThreshold}}{{if .Autocert.Challenge}}
  challenge:
    port: {{.Autocert.Challenge.Port}}{{if .Autocert.Challenge.Path}}
    path: "{{.Autocert.Challenge.Path}}"{{end}}{{if .Autocert.Challenge.Timeout}}
    timeout: "{{.Autocert.Challenge.Timeout}}"{{end}}{{end}}{{if .Autocert.RateLimit}}
  rate_limit:
    requests_per_second: {{.Autocert.RateLimit.RequestsPerSecond}}
    burst: {{.Autocert.RateLimit.Burst}}{{end}}{{if .Autocert.Retry}}
  retry:
    max_attempts: {{.Autocert.Retry.MaxAttempts}}{{if .Autocert.Retry.InitialDelay}}
    initial_delay: "{{.Autocert.Retry.InitialDelay}}"{{end}}{{if .Autocert.Retry.MaxDelay}}
    max_delay: "{{.Autocert.Retry.MaxDelay}}"{{end}}{{end}}
{{end}}{{if .CORS}}
# CORS (Cross-Origin Resource Sharing) settings for SPA development
cors:
  enabled: {{.CORS.Enabled}}{{if .CORS.AllowedOrigins}}
  allowed_origins:{{range .CORS.AllowedOrigins}}
    - "{{.}}"{{end}}{{else}}
  # allowed_origins:
  #   - "http://localhost:3000"
  #   - "https://example.com"{{end}}{{if .CORS.AllowedMethods}}
  allowed_methods:{{range .CORS.AllowedMethods}}
    - "{{.}}"{{end}}{{else}}
  # allowed_methods:
  #   - "GET"
  #   - "POST"
  #   - "OPTIONS"{{end}}{{if .CORS.AllowedHeaders}}
  allowed_headers:{{range .CORS.AllowedHeaders}}
    - "{{.}}"{{end}}{{else}}
  # allowed_headers:
  #   - "Content-Type"
  #   - "Authorization"{{end}}
{{end}}
# User definitions
users:{{range $userID, $user := .Users}}
  {{$userID}}:
    display_name: "{{$user.DisplayName}}"{{if $user.ExtraValidScopes}}
    extra_valid_scopes:{{range $user.ExtraValidScopes}}
      - "{{.}}"{{end}}{{end}}{{if $user.ExtraClaims}}
    extra_claims:{{range $key, $value := $user.ExtraClaims}}
      {{$key}}: {{if eq (printf "%T" $value) "string"}}"{{$value}}"{{else}}{{$value}}{{end}}{{end}}{{end}}{{end}}
`

	t, err := template.New("config").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var result strings.Builder
	if err := t.Execute(&result, config); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return result.String(), nil
}

// AddUser adds a new user to the configuration
func AddUser(configPath, userID string, user User) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if config.Users == nil {
		config.Users = make(map[string]User)
	}

	config.Users[userID] = user

	return SaveConfig(configPath, config)
}

// RemoveUser removes a user from the configuration
func RemoveUser(configPath, userID string) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if config.Users == nil {
		return ErrNoUsersConfigured
	}

	if _, exists := config.Users[userID]; !exists {
		return fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	delete(config.Users, userID)

	return SaveConfig(configPath, config)
}

// ModifyConfig modifies configuration settings
func ModifyConfig(configPath string, updates map[string]any) error {
	config, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Apply updates
	for key, value := range updates {
		if err := applyConfigUpdate(config, key, value); err != nil {
			return fmt.Errorf("failed to apply update %s: %w", key, err)
		}
	}

	return SaveConfig(configPath, config)
}

// applyConfigUpdate applies a single configuration update
func applyConfigUpdate(config *Config, key string, value any) error {
	switch key {
	case "pkce_required":
		if v, ok := value.(bool); ok {
			config.OIDCLD.PKCERequired = v
		}
	case "nonce_required":
		if v, ok := value.(bool); ok {
			config.OIDCLD.NonceRequired = v
		}
	case "expired_in":
		if v, ok := value.(int); ok {
			config.OIDCLD.ExpiredIn = v
		}
	case "issuer", "iss":
		if v, ok := value.(string); ok {
			config.OIDCLD.Issuer = v
		}
	case "refresh_token_enabled":
		if v, ok := value.(bool); ok {
			config.OIDCLD.RefreshTokenEnabled = v
		}
	case "refresh_token_expiry":
		if v, ok := value.(int); ok {
			config.OIDCLD.RefreshTokenExpiry = v
		}
	case "autocert_enabled":
		if config.Autocert == nil {
			config.Autocert = &AutocertConfig{}
		}
		if v, ok := value.(bool); ok {
			config.Autocert.Enabled = v
		}
	case "autocert_email":
		if config.Autocert == nil {
			config.Autocert = &AutocertConfig{}
		}
		if v, ok := value.(string); ok {
			config.Autocert.Email = v
		}
	case "autocert_cache_dir":
		if config.Autocert == nil {
			config.Autocert = &AutocertConfig{}
		}
		if v, ok := value.(string); ok {
			config.Autocert.CacheDir = v
		}
	default:
		return fmt.Errorf("%w: %s", ErrUnknownConfigKey, key)
	}
	return nil
}

// GenerateCertificates generates cryptographic keys based on the specified algorithm
func GenerateCertificates(algorithm string, cfg *Config) error {
	// Set algorithm in config
	cfg.OIDCLD.Algorithm = algorithm

	// Set key file paths
	cfg.OIDCLD.PrivateKeyPath = ".oidcld.key"
	cfg.OIDCLD.PublicKeyPath = ".openidld.pub.key"

	// Generate keys based on algorithm
	switch {
	case strings.HasPrefix(algorithm, "RS"):
		return generateRSAKeys(algorithm)
	case strings.HasPrefix(algorithm, "ES"):
		return generateECDSAKeys(algorithm)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}
}

// generateRSAKeys generates RSA key pair
func generateRSAKeys(algorithm string) error {
	// Determine key size based on algorithm
	var keySize int
	switch algorithm {
	case "RS256":
		keySize = 2048
	case "RS384":
		keySize = 3072
	case "RS512":
		keySize = 4096
	default:
		keySize = 2048
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	// Save private key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyFile, err := os.Create(".oidcld.key")
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	if err := os.Chmod(".oidcld.key", 0600); err != nil {
		return fmt.Errorf("failed to set private key file permissions: %w", err)
	}

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	publicKeyPKCS1 := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKCS1,
	}

	publicKeyFile, err := os.Create(".openidld.pub.key")
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicKeyFile.Close()

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// generateECDSAKeys generates ECDSA key pair
func generateECDSAKeys(algorithm string) error {
	// Determine curve based on algorithm
	var curve elliptic.Curve
	switch algorithm {
	case "ES256":
		curve = elliptic.P256()
	case "ES384":
		curve = elliptic.P384()
	case "ES512":
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	// Save private key
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyFile, err := os.Create(".oidcld.key")
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	if err := os.Chmod(".oidcld.key", 0600); err != nil {
		return fmt.Errorf("failed to set private key file permissions: %w", err)
	}

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKeyFile, err := os.Create(".openidld.pub.key")
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicKeyFile.Close()

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// ValidateAutocertConfig validates the autocert configuration.
func (c *Config) ValidateAutocertConfig() error {
	if c.Autocert == nil || !c.Autocert.Enabled {
		return nil // Disabled or nil autocert is valid
	}

	if len(c.Autocert.Domains) == 0 {
		return fmt.Errorf("autocert.domains is required when autocert is enabled")
	}

	if c.Autocert.Email == "" {
		return fmt.Errorf("autocert.email is required when autocert is enabled")
	}

	if !c.Autocert.AgreeTOS {
		return fmt.Errorf("autocert.agree_tos must be true when autocert is enabled")
	}

	// Set defaults for optional fields
	if c.Autocert.CacheDir == "" {
		c.Autocert.CacheDir = "./autocert-cache"
	}

	// If not set (0) or negative, default to 30 days
	if c.Autocert.RenewalThreshold <= 0 {
		c.Autocert.RenewalThreshold = 30 // Default to 30 days
	}

	// Set ACME server based on staging flag if not explicitly set
	if c.Autocert.ACMEServer == "" {
		if c.Autocert.Staging {
			c.Autocert.ACMEServer = "https://acme-staging-v02.api.letsencrypt.org/directory"
		} else {
			c.Autocert.ACMEServer = "https://acme-v02.api.letsencrypt.org/directory"
		}
	}

	// Set challenge defaults
	if c.Autocert.Challenge != nil {
		if c.Autocert.Challenge.Port <= 0 {
			c.Autocert.Challenge.Port = 80
		}
		if c.Autocert.Challenge.Path == "" {
			c.Autocert.Challenge.Path = "/.well-known/acme-challenge/"
		}
		if c.Autocert.Challenge.Timeout == "" {
			c.Autocert.Challenge.Timeout = "30s"
		}
	}

	// Set rate limit defaults
	if c.Autocert.RateLimit != nil {
		if c.Autocert.RateLimit.RequestsPerSecond <= 0 {
			c.Autocert.RateLimit.RequestsPerSecond = 10
		}
		if c.Autocert.RateLimit.Burst <= 0 {
			c.Autocert.RateLimit.Burst = 20
		}
	}

	// Set retry defaults
	if c.Autocert.Retry != nil {
		if c.Autocert.Retry.MaxAttempts <= 0 {
			c.Autocert.Retry.MaxAttempts = 3
		}
		if c.Autocert.Retry.InitialDelay == "" {
			c.Autocert.Retry.InitialDelay = "1s"
		}
		if c.Autocert.Retry.MaxDelay == "" {
			c.Autocert.Retry.MaxDelay = "30s"
		}
	}
	return nil
}

// GetAutocertDefaults returns a default AutocertConfig with all default values set.
func GetAutocertDefaults() *AutocertConfig {
	return &AutocertConfig{
		Enabled:          false,
		Domains:          []string{},
		Email:            "",
		AgreeTOS:         false,
		CacheDir:         "./autocert-cache",
		ACMEServer:       "https://acme-v02.api.letsencrypt.org/directory",
		Staging:          false,
		RenewalThreshold: 30,
		Challenge: &AutocertChallengeConfig{
			Port:    80,
			Path:    "/.well-known/acme-challenge/",
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
	}
}

// LoadConfig loads configuration from file, applying environment-based
// autocert overrides (OIDCLD_ACME_ prefixed vars) and optional verbose
// logging. This consolidates the previous split helper functions.
func LoadConfig(configPath string, verbose bool) (*Config, error) {
	// Load base configuration from file
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	// Apply verbose logging override
	if verbose {
		cfg.OIDCLD.VerboseLogging = true
	}

	// Collect environment-based autocert overrides
	var any bool
	o := &AutocertOverrides{RenewalThreshold: -1}

	if v := os.Getenv("OIDCLD_ACME_DIRECTORY_URL"); v != "" {
		o.ACMEDirectoryURL = v
		any = true
	}
	if v := os.Getenv("OIDCLD_ACME_EMAIL"); v != "" {
		o.Email = v
		any = true
	}
	if v := os.Getenv("OIDCLD_ACME_DOMAIN"); v != "" {
		o.Domain = v
		any = true
	}
	if v := os.Getenv("OIDCLD_ACME_CACHE_DIR"); v != "" {
		o.CacheDir = v
		any = true
	}
	if v := os.Getenv("OIDCLD_ACME_AGREE_TOS"); v != "" {
		b, _ := strconv.ParseBool(v)
		o.AgreeTOS = b
		if b {
			any = true
		}
	}
	if v := os.Getenv("OIDCLD_ACME_INSECURE_SKIP_VERIFY"); v != "" {
		b, _ := strconv.ParseBool(v)
		o.InsecureSkipVerify = b
		if b {
			any = true
		}
	}
	if v := os.Getenv("OIDCLD_ACME_RENEWAL_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			o.RenewalThreshold = n
			any = true
		}
	}

	// If any overrides were found, apply them. If none, do nothing.
	if any {
		if err := applyAutocertOverrides(cfg, o); err != nil {
			return nil, fmt.Errorf("failed to apply autocert overrides: %w", err)
		}
	}

	return cfg, nil
}

// AutocertOverrides represents environment variable overrides for autocert
type AutocertOverrides struct {
	ACMEDirectoryURL   string
	Email              string
	Domain             string
	CacheDir           string
	AgreeTOS           bool
	InsecureSkipVerify bool
	RenewalThreshold   int
}

// loadAutocertOverridesFromEnv reads environment variables with the
// OIDCLD_ACME_ prefix and returns an AutocertOverrides struct if any
// relevant variables are present. Returns nil if no overrides found.
// (loadAutocertOverridesFromEnv removed; logic merged into LoadConfig)

// applyAutocertOverrides applies autocert environment variable overrides to configuration
func applyAutocertOverrides(cfg *Config, overrides *AutocertOverrides) error {
	// Determine whether any autocert-related environment variables are present.
	// If so, prefer environment (Docker) and enable autocert even when the
	// file config explicitly disables it.
	present := overrides != nil && (overrides.ACMEDirectoryURL != "" || overrides.Email != "" || overrides.Domain != "" || overrides.CacheDir != "" || overrides.AgreeTOS || overrides.InsecureSkipVerify || overrides.RenewalThreshold >= 0)

	// Initialize autocert config if not present and environment variables are set
	if cfg.Autocert == nil && present {
		cfg.Autocert = &AutocertConfig{
			Enabled: true,
		}
	}

	// If autocert exists in file but environment overrides are present,
	// allow env to enable autocert (env should take precedence in Docker mode).
	if cfg.Autocert != nil && present {
		cfg.Autocert.Enabled = true
	}

	// Apply environment variable overrides if autocert is configured
	if cfg.Autocert != nil {
		// ACME Directory URL
		if overrides.ACMEDirectoryURL != "" {
			cfg.Autocert.ACMEServer = overrides.ACMEDirectoryURL
			cfg.Autocert.Enabled = true
		}

		// Email for ACME registration
		if overrides.Email != "" {
			cfg.Autocert.Email = overrides.Email
		}

		// Domain(s) for certificate
		if overrides.Domain != "" {
			// Split comma-separated domains
			domains := strings.Split(overrides.Domain, ",")
			for i, domain := range domains {
				domains[i] = strings.TrimSpace(domain)
			}
			cfg.Autocert.Domains = domains
		}

		// Cache directory
		if overrides.CacheDir != "" {
			cfg.Autocert.CacheDir = overrides.CacheDir
		}

		// Agree to Terms of Service
		if overrides.AgreeTOS {
			cfg.Autocert.AgreeTOS = true
		}

		// Insecure skip verify
		if overrides.InsecureSkipVerify {
			cfg.Autocert.InsecureSkipVerify = true
		}

		// Renewal threshold
		if overrides.RenewalThreshold >= 0 {
			cfg.Autocert.RenewalThreshold = overrides.RenewalThreshold
		}

		// Set default cache directory if not specified
		if cfg.Autocert.CacheDir == "" {
			cfg.Autocert.CacheDir = "/tmp/autocert"
		}
	}

	return nil
}
