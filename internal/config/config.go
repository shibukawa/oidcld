// Package config provides functionality to manage OIDCLD configuration
package config

import (
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/goccy/go-yaml"
)

var (
	ErrAutocertDomainsRequired              = errors.New("autocert.domains is required when autocert is enabled")
	ErrAutocertEmailRequired                = errors.New("autocert.email is required when autocert is enabled")
	ErrAutocertAgreeTOS                     = errors.New("autocert.agree_tos must be true when autocert is enabled")
	ErrAutocertConflict                     = errors.New("autocert is enabled but TLS cert/key are also configured in oidcld config; choose one method")
	ErrAccessFilterNegativeMaxForwardedHops = errors.New("oidcld.access_filter.max_forwarded_hops must be >= 0")
	ErrAccessFilterEmptyAllowedIPEntry      = errors.New("oidcld.access_filter.extra_allowed_ips contains an empty entry")
	ErrAccessFilterInvalidAllowedIPEntry    = errors.New("invalid oidcld.access_filter.extra_allowed_ips entry")
	ErrLoginUIInvalidAccentColor            = errors.New("oidcld.login_ui.accent_color must be a hex color like #RRGGBB")
)

// Static errors for better error handling.
var (
	ErrNoUsersConfigured = errors.New("no users configured")
	ErrUserNotFound      = errors.New("user not found")
	ErrUnknownConfigKey  = errors.New("unknown configuration key")
)

// Config represents the OIDCLD configuration.
type Config struct {
	OIDCLD   OIDCLDConfig    `yaml:"oidcld"`
	EntraID  *EntraIDConfig  `yaml:"entraid,omitempty"`
	CORS     *CORSConfig     `yaml:"cors,omitempty"`
	Autocert *AutocertConfig `yaml:"autocert,omitempty"`
	Users    map[string]User `yaml:"users"`

	sourceDir string `yaml:"-"`
}

// OIDCLDConfig represents the core OpenID Connect configuration.
type OIDCLDConfig struct {
	Issuer              string              `yaml:"iss,omitempty"`
	PKCERequired        bool                `yaml:"pkce_required,omitempty"`
	NonceRequired       bool                `yaml:"nonce_required,omitempty"`
	ExpiredIn           int                 `yaml:"expired_in,omitempty"` // Token expiration in seconds
	AudienceClaimFormat string              `yaml:"aud_claim_format,omitempty"`
	ValidScopes         []string            `yaml:"valid_scopes,omitempty"`
	AccessFilter        *AccessFilterConfig `yaml:"access_filter,omitempty"`
	LoginUI             *LoginUIConfig      `yaml:"login_ui,omitempty"`
	// TLS certificate file paths for serving HTTPS when not using autocert.
	TLSCertFile               string `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile                string `yaml:"tls_key_file,omitempty"`
	RefreshTokenEnabled       bool   `yaml:"refresh_token_enabled,omitempty"`
	RefreshTokenExpiry        int    `yaml:"refresh_token_expiry,omitempty"`
	EndSessionEnabled         bool   `yaml:"end_session_enabled,omitempty"`
	EndSessionEndpointVisible bool   `yaml:"end_session_endpoint_visible,omitempty"`
	VerboseLogging            bool   `yaml:"verbose_logging,omitempty"`
}

const (
	AudienceClaimFormatString = "string"
	AudienceClaimFormatArray  = "array"
	DefaultHTTPPort           = "18888"
	DefaultHTTPSPort          = "18443"
)

func normalizeAudienceClaimFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case AudienceClaimFormatArray:
		return AudienceClaimFormatArray
	default:
		return AudienceClaimFormatString
	}
}

func (c OIDCLDConfig) NormalizedAudienceClaimFormat() string {
	return normalizeAudienceClaimFormat(c.AudienceClaimFormat)
}

func DefaultAccessFilterConfig() *AccessFilterConfig {
	return &AccessFilterConfig{
		Enabled:          true,
		ExtraAllowedIPs:  []string{},
		MaxForwardedHops: 0,
	}
}

func DefaultServePort(useHTTPS bool) string {
	if useHTTPS {
		return DefaultHTTPSPort
	}
	return DefaultHTTPPort
}

// ensureDefaultScopes ensures that standard OIDC scopes are present in the provided config.
// When isEntra is true (EntraID compatibility modes), `address` and `phone` are not added
// because EntraID does not expose them in the same way.
func ensureDefaultScopes(cfg *OIDCLDConfig, isEntra bool) {
	if cfg == nil {
		return
	}

	// base standard OIDC scopes we want to guarantee
	std := []string{"openid", "profile", "email", "offline_access"}

	// include address/phone only for non-Entra configurations
	if !isEntra {
		std = append(std, "address", "phone")
	}

	// build a set of existing scopes (lowercased for safety)
	exist := map[string]bool{}
	for _, s := range cfg.ValidScopes {
		exist[strings.ToLower(s)] = true
	}

	// append missing standard scopes preserving existing order
	for _, s := range std {
		if !exist[strings.ToLower(s)] {
			cfg.ValidScopes = append(cfg.ValidScopes, s)
			exist[strings.ToLower(s)] = true
		}
	}
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

// AccessFilterConfig represents local-only filtering for serve listeners.
type AccessFilterConfig struct {
	Enabled          bool     `yaml:"enabled,omitempty"`
	ExtraAllowedIPs  []string `yaml:"extra_allowed_ips,omitempty"`
	MaxForwardedHops int      `yaml:"max_forwarded_hops,omitempty"`
}

// LoginUIConfig configures login-page-specific environment cues.
type LoginUIConfig struct {
	EnvTitle         string `yaml:"env_title,omitempty"`
	AccentColor      string `yaml:"accent_color,omitempty"`
	InfoMarkdownFile string `yaml:"info_markdown_file,omitempty"`

	resolvedAccentColor      string `yaml:"-"`
	resolvedTextColor        string `yaml:"-"`
	resolvedInfoMarkdownFile string `yaml:"-"`
}

func (c *LoginUIConfig) HasEnvironmentBanner() bool {
	return c != nil && strings.TrimSpace(c.EnvTitle) != ""
}

func (c *LoginUIConfig) EffectiveAccentColor() string {
	if c == nil {
		return ""
	}
	if c.resolvedAccentColor != "" {
		return c.resolvedAccentColor
	}
	return strings.TrimSpace(c.AccentColor)
}

func (c *LoginUIConfig) EffectiveTextColor() string {
	if c == nil {
		return ""
	}
	return c.resolvedTextColor
}

func (c *LoginUIConfig) EffectiveInfoMarkdownFile() string {
	if c == nil {
		return ""
	}
	if c.resolvedInfoMarkdownFile != "" {
		return c.resolvedInfoMarkdownFile
	}
	return strings.TrimSpace(c.InfoMarkdownFile)
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

	if err := config.setSourceDir(configPath); err != nil {
		return nil, err
	}

	if err := config.Normalize(); err != nil {
		return nil, err
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

	if err := config.setSourceDir(absPath); err != nil {
		return err
	}
	if err := config.Normalize(); err != nil {
		return err
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
	// Define base user data
	baseUsers := map[string]User{
		"admin": {
			DisplayName:      "Administrator",
			ExtraValidScopes: []string{"admin", "read", "write"},
			ExtraClaims: map[string]any{
				"email":       "admin@example.com",
				"role":        "admin",
				"given_name":  "Admin",
				"family_name": "User",
				"department":  "IT",
			},
		},
		"user": {
			DisplayName:      "Regular User",
			ExtraValidScopes: []string{"read"},
			ExtraClaims: map[string]any{
				"email":       "user@example.com",
				"role":        "user",
				"given_name":  "Regular",
				"family_name": "User",
				"department":  "General",
			},
		},
		"manager": {
			DisplayName:      "Project Manager",
			ExtraValidScopes: []string{"read", "write"},
			ExtraClaims: map[string]any{
				"email":       "manager@example.com",
				"role":        "manager",
				"given_name":  "Project",
				"family_name": "Manager",
				"department":  "Operations",
				"teams":       []string{"development", "qa"},
			},
		},
		"developer": {
			DisplayName:      "Software Developer",
			ExtraValidScopes: []string{"read", "write"},
			ExtraClaims: map[string]any{
				"email":       "developer@example.com",
				"role":        "developer",
				"given_name":  "John",
				"family_name": "Doe",
				"department":  "Engineering",
				"skills":      []string{"golang", "javascript", "react"},
				"employee_id": "EMP001",
			},
		},
		"analyst": {
			DisplayName:      "Data Analyst",
			ExtraValidScopes: []string{"read"},
			ExtraClaims: map[string]any{
				"email":       "analyst@example.com",
				"role":        "analyst",
				"given_name":  "Jane",
				"family_name": "Smith",
				"department":  "Analytics",
				"tools":       []string{"sql", "python", "tableau"},
				"employee_id": "EMP002",
			},
		},
		"guest": {
			DisplayName: "Guest User",
			ExtraClaims: map[string]any{
				"email":       "guest@example.com",
				"role":        "guest",
				"given_name":  "Guest",
				"family_name": "User",
				"access_type": "temporary",
			},
		},
	}

	// Add EntraID-specific claims when in EntraID mode
	var users map[string]User
	if mode == ModeEntraIDv1 || mode == ModeEntraIDv2 {
		users = make(map[string]User)
		tenantID := "common"
		if mode == ModeEntraIDv2 {
			tenantID = "12345678-1234-1234-1234-123456789abc"
		}

		for userID, user := range baseUsers {
			// Create a copy of the user
			newUser := User{
				DisplayName:      user.DisplayName,
				ExtraValidScopes: user.ExtraValidScopes,
				ExtraClaims:      make(map[string]any),
			}

			// Copy base claims
			maps.Copy(newUser.ExtraClaims, user.ExtraClaims)

			// Add EntraID-specific claims
			switch userID {
			case "admin":
				newUser.ExtraClaims["oid"] = "00000000-0000-0000-0000-000000000001"
				newUser.ExtraClaims["tid"] = tenantID
				newUser.ExtraClaims["preferred_username"] = "admin@contoso.com"
				newUser.ExtraClaims["upn"] = "admin@contoso.com"
				newUser.ExtraClaims["roles"] = []string{"GlobalAdmin", "UserAdmin"}
				newUser.ExtraClaims["groups"] = []string{"Administrators", "IT Staff"}
				newUser.ExtraClaims["app_displayname"] = "OIDCLD Test Server"
			case "user":
				newUser.ExtraClaims["oid"] = "00000000-0000-0000-0000-000000000002"
				newUser.ExtraClaims["tid"] = tenantID
				newUser.ExtraClaims["preferred_username"] = "user@contoso.com"
				newUser.ExtraClaims["upn"] = "user@contoso.com"
				newUser.ExtraClaims["roles"] = []string{"User"}
				newUser.ExtraClaims["groups"] = []string{"Users"}
				newUser.ExtraClaims["app_displayname"] = "OIDCLD Test Server"
			case "manager":
				newUser.ExtraClaims["oid"] = "00000000-0000-0000-0000-000000000003"
				newUser.ExtraClaims["tid"] = tenantID
				newUser.ExtraClaims["preferred_username"] = "manager@contoso.com"
				newUser.ExtraClaims["upn"] = "manager@contoso.com"
				newUser.ExtraClaims["roles"] = []string{"ProjectManager", "User"}
				newUser.ExtraClaims["groups"] = []string{"Managers", "Operations"}
				newUser.ExtraClaims["app_displayname"] = "OIDCLD Test Server"
			case "developer":
				newUser.ExtraClaims["oid"] = "00000000-0000-0000-0000-000000000004"
				newUser.ExtraClaims["tid"] = tenantID
				newUser.ExtraClaims["preferred_username"] = "developer@contoso.com"
				newUser.ExtraClaims["upn"] = "developer@contoso.com"
				newUser.ExtraClaims["roles"] = []string{"Developer", "User"}
				newUser.ExtraClaims["groups"] = []string{"Developers", "Engineering"}
				newUser.ExtraClaims["app_displayname"] = "OIDCLD Test Server"
			case "analyst":
				newUser.ExtraClaims["oid"] = "00000000-0000-0000-0000-000000000005"
				newUser.ExtraClaims["tid"] = tenantID
				newUser.ExtraClaims["preferred_username"] = "analyst@contoso.com"
				newUser.ExtraClaims["upn"] = "analyst@contoso.com"
				newUser.ExtraClaims["roles"] = []string{"Analyst", "User"}
				newUser.ExtraClaims["groups"] = []string{"Analytics", "DataTeam"}
				newUser.ExtraClaims["app_displayname"] = "OIDCLD Test Server"
			case "guest":
				newUser.ExtraClaims["oid"] = "00000000-0000-0000-0000-000000000006"
				newUser.ExtraClaims["tid"] = tenantID
				newUser.ExtraClaims["preferred_username"] = "guest@contoso.com"
				newUser.ExtraClaims["upn"] = "guest@contoso.com"
				newUser.ExtraClaims["roles"] = []string{"Guest"}
				newUser.ExtraClaims["groups"] = []string{"Guests"}
				newUser.ExtraClaims["app_displayname"] = "OIDCLD Test Server"
			}

			users[userID] = newUser
		}
	} else {
		users = baseUsers
	}

	config := &Config{
		OIDCLD: OIDCLDConfig{
			PKCERequired:              false,
			NonceRequired:             false,
			ExpiredIn:                 3600,
			AudienceClaimFormat:       AudienceClaimFormatString,
			ValidScopes:               []string{"admin", "read", "write"},
			AccessFilter:              DefaultAccessFilterConfig(),
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
		Users: users,
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

	if err := config.Normalize(); err != nil {
		panic(err)
	}

	return config
}

// InitServerOptions contains the values coming from the CLI init command that
// influence server-related parts of the configuration.
type InitServerOptions struct {
	TenantID         string
	Port             string
	Issuer           string
	HTTPS            bool
	Autocert         bool
	ACMEServer       string
	Domains          []string
	Email            string
	AutocertCacheDir string
}

// HealthOptions contains options related to healthcheck behavior.
type HealthOptions struct {
	InsecureSkipVerify bool
}

// ApplyInitServerOptions applies initialization options (from CLI) to the
// configuration. mode is the initialization mode that influenced defaults.
func (c *Config) ApplyInitServerOptions(mode Mode, opts *InitServerOptions) {
	if opts == nil {
		return
	}

	// Tenant / EntraID handling
	if opts.TenantID != "" {
		if c.EntraID == nil {
			c.EntraID = &EntraIDConfig{Version: "v1"}
		}
		c.EntraID.TenantID = opts.TenantID
		// For EntraID v2 set issuer if not explicitly overridden
		if mode == ModeEntraIDv2 {
			c.OIDCLD.Issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", opts.TenantID)
		}
	}

	// Issuer selection precedence mirrors init wizard logic
	switch {
	case opts.Port != "" && opts.Issuer != "":
		c.OIDCLD.Issuer = opts.Issuer
	case opts.Port != "" && mode == ModeStandard:
		if opts.HTTPS {
			c.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", opts.Port)
		} else {
			c.OIDCLD.Issuer = fmt.Sprintf("http://localhost:%s", opts.Port)
		}
	case opts.Issuer != "":
		c.OIDCLD.Issuer = opts.Issuer
	case mode == ModeStandard:
		defaultPort := DefaultServePort(opts.HTTPS)
		if opts.HTTPS {
			c.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", defaultPort)
		} else {
			c.OIDCLD.Issuer = fmt.Sprintf("http://localhost:%s", defaultPort)
		}
	}

	// Autocert mapping
	if opts.Autocert {
		if c.Autocert == nil {
			c.Autocert = &AutocertConfig{}
		}
		c.Autocert.Enabled = true
		if opts.ACMEServer != "" {
			c.Autocert.ACMEServer = opts.ACMEServer
		}
		if opts.Email != "" {
			c.Autocert.Email = opts.Email
		}
		// Default cache dir if not provided by caller
		if opts.AutocertCacheDir != "" {
			c.Autocert.CacheDir = opts.AutocertCacheDir
		} else if c.Autocert.CacheDir == "" {
			c.Autocert.CacheDir = "/tmp/autocert"
		}
		if len(opts.Domains) > 0 {
			c.Autocert.Domains = opts.Domains
		}
	}
}

// ApplyHealthOptions applies healthcheck-related options to the configuration.
func (c *Config) ApplyHealthOptions(opts *HealthOptions) {
	if opts == nil {
		return
	}
	if c.Autocert == nil {
		return
	}
	if opts.InsecureSkipVerify {
		c.Autocert.InsecureSkipVerify = true
	}
}

// ServeOptions contains parameters used by the serve command to prepare the
// configuration before starting the server.
type ServeOptions struct {
	Port    string
	Verbose bool
}

// PrepareForServe applies serve-time defaults to the configuration and returns
// whether HTTPS should be used and an optional message (e.g., auto-enable hint).
func (c *Config) PrepareForServe(opts *ServeOptions) (useHTTPS bool, message string) {
	if opts == nil {
		return false, ""
	}

	// Determine HTTPS from existing issuer or autocert
	if c.OIDCLD.Issuer != "" && strings.HasPrefix(c.OIDCLD.Issuer, "https://") {
		useHTTPS = true
	}
	if c.Autocert != nil && c.Autocert.Enabled {
		useHTTPS = true
		message = "🔧 Auto-enabling HTTPS mode due to autocert configuration"
	}

	// Ensure issuer is set appropriately if missing
	if c.OIDCLD.Issuer == "" {
		if useHTTPS {
			c.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", opts.Port)
		} else {
			c.OIDCLD.Issuer = fmt.Sprintf("http://localhost:%s", opts.Port)
		}
	}
	c.OIDCLD.Issuer = NormalizeIssuerForServe(c.OIDCLD.Issuer, opts.Port, c.EntraID)

	return useHTTPS, message
}

// Normalize applies runtime defaults and validates the configuration.
func (c *Config) Normalize() error {
	if c == nil {
		return nil
	}

	isEntra := c.EntraID != nil
	ensureDefaultScopes(&c.OIDCLD, isEntra)
	c.OIDCLD.AudienceClaimFormat = normalizeAudienceClaimFormat(c.OIDCLD.AudienceClaimFormat)

	accessFilter, err := normalizeAccessFilterConfig(c.OIDCLD.AccessFilter)
	if err != nil {
		return err
	}
	c.OIDCLD.AccessFilter = accessFilter

	loginUI, omitLoginUI, err := normalizeLoginUIConfig(c.OIDCLD.LoginUI, c.sourceDir)
	if err != nil {
		return err
	}
	if omitLoginUI {
		c.OIDCLD.LoginUI = nil
	} else {
		c.OIDCLD.LoginUI = loginUI
	}

	return nil
}

func (c *Config) setSourceDir(configPath string) error {
	if c == nil || strings.TrimSpace(configPath) == "" {
		return nil
	}

	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}
	c.sourceDir = filepath.Dir(absPath)
	return nil
}

func normalizeAccessFilterConfig(cfg *AccessFilterConfig) (*AccessFilterConfig, error) {
	normalized := DefaultAccessFilterConfig()
	if cfg != nil {
		normalized.Enabled = cfg.Enabled
		normalized.ExtraAllowedIPs = append([]string{}, cfg.ExtraAllowedIPs...)
		normalized.MaxForwardedHops = cfg.MaxForwardedHops
	}

	if normalized.MaxForwardedHops < 0 {
		return nil, ErrAccessFilterNegativeMaxForwardedHops
	}

	entries, err := normalizeAllowedIPEntries(normalized.ExtraAllowedIPs)
	if err != nil {
		return nil, err
	}
	normalized.ExtraAllowedIPs = entries

	return normalized, nil
}

func normalizeAllowedIPEntries(entries []string) ([]string, error) {
	if len(entries) == 0 {
		return []string{}, nil
	}

	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		value, err := normalizeAllowedIPEntry(entry)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, value)
	}

	return normalized, nil
}

func normalizeAllowedIPEntry(entry string) (string, error) {
	value := strings.TrimSpace(entry)
	if value == "" {
		return "", ErrAccessFilterEmptyAllowedIPEntry
	}

	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return "", fmt.Errorf("%w %q: %w", ErrAccessFilterInvalidAllowedIPEntry, entry, err)
		}
		return ipNet.String(), nil
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("%w %q", ErrAccessFilterInvalidAllowedIPEntry, entry)
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return (&net.IPNet{IP: ipv4, Mask: net.CIDRMask(32, 32)}).String(), nil
	}
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}).String(), nil
}

func normalizeLoginUIConfig(cfg *LoginUIConfig, sourceDir string) (*LoginUIConfig, bool, error) {
	if cfg == nil {
		return nil, true, nil
	}

	cfg.EnvTitle = strings.TrimSpace(cfg.EnvTitle)
	cfg.AccentColor = strings.TrimSpace(cfg.AccentColor)
	cfg.InfoMarkdownFile = strings.TrimSpace(cfg.InfoMarkdownFile)
	cfg.resolvedAccentColor = ""
	cfg.resolvedTextColor = ""
	cfg.resolvedInfoMarkdownFile = ""

	if cfg.EnvTitle == "" && cfg.AccentColor == "" && cfg.InfoMarkdownFile == "" {
		return nil, true, nil
	}

	if cfg.AccentColor != "" {
		normalizedColor, err := normalizeHexColor(cfg.AccentColor)
		if err != nil {
			return nil, false, err
		}
		cfg.AccentColor = normalizedColor
		cfg.resolvedAccentColor = normalizedColor
	} else if cfg.EnvTitle != "" {
		cfg.resolvedAccentColor = generateAccentColorFromTitle(cfg.EnvTitle)
	}

	if cfg.InfoMarkdownFile != "" {
		resolvedPath, err := resolveConfigRelativePath(sourceDir, cfg.InfoMarkdownFile)
		if err != nil {
			return nil, false, err
		}
		cfg.resolvedInfoMarkdownFile = resolvedPath
	}

	if accent := cfg.EffectiveAccentColor(); accent != "" {
		cfg.resolvedTextColor = contrastTextColor(accent)
	}

	return cfg, false, nil
}

func resolveConfigRelativePath(sourceDir, rawPath string) (string, error) {
	trimmedPath := strings.TrimSpace(rawPath)
	if trimmedPath == "" {
		return "", nil
	}
	if filepath.IsAbs(trimmedPath) {
		return filepath.Clean(trimmedPath), nil
	}
	if strings.TrimSpace(sourceDir) == "" {
		absPath, err := filepath.Abs(trimmedPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve login_ui.info_markdown_file: %w", err)
		}
		return filepath.Clean(absPath), nil
	}
	return filepath.Clean(filepath.Join(sourceDir, trimmedPath)), nil
}

func normalizeHexColor(value string) (string, error) {
	trimmedValue := strings.TrimSpace(value)
	if len(trimmedValue) != 7 || trimmedValue[0] != '#' {
		return "", ErrLoginUIInvalidAccentColor
	}

	var normalized strings.Builder
	normalized.Grow(len(trimmedValue))
	normalized.WriteByte('#')
	for i := 1; i < len(trimmedValue); i++ {
		ch := trimmedValue[i]
		switch {
		case ch >= '0' && ch <= '9':
			normalized.WriteByte(ch)
		case ch >= 'a' && ch <= 'f':
			normalized.WriteByte(ch - ('a' - 'A'))
		case ch >= 'A' && ch <= 'F':
			normalized.WriteByte(ch)
		default:
			return "", ErrLoginUIInvalidAccentColor
		}
	}

	return normalized.String(), nil
}

func generateAccentColorFromTitle(title string) string {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(title)))
	hashValue := hasher.Sum32()

	hue := float64(hashValue % 360)
	saturation := 0.60 + float64((hashValue>>9)%11)/100.0
	value := 0.78 + float64((hashValue>>17)%11)/100.0

	red, green, blue := hsvToRGB(hue, saturation, value)
	return fmt.Sprintf("#%02X%02X%02X", red, green, blue)
}

func hsvToRGB(hue, saturation, value float64) (int, int, int) {
	chroma := value * saturation
	segment := hue / 60.0
	x := chroma * (1 - math.Abs(math.Mod(segment, 2)-1))

	var redPrime, greenPrime, bluePrime float64
	switch {
	case segment < 1:
		redPrime, greenPrime = chroma, x
	case segment < 2:
		redPrime, greenPrime = x, chroma
	case segment < 3:
		greenPrime, bluePrime = chroma, x
	case segment < 4:
		greenPrime, bluePrime = x, chroma
	case segment < 5:
		redPrime, bluePrime = x, chroma
	default:
		redPrime, bluePrime = chroma, x
	}

	match := value - chroma
	red := int(math.Round((redPrime + match) * 255))
	green := int(math.Round((greenPrime + match) * 255))
	blue := int(math.Round((bluePrime + match) * 255))

	return red, green, blue
}

func contrastTextColor(hexColor string) string {
	if len(hexColor) != 7 || hexColor[0] != '#' {
		return "#111111"
	}

	parseChannel := func(value string) int64 {
		channel, err := strconv.ParseInt(value, 16, 64)
		if err != nil {
			return 0
		}
		return channel
	}

	red := parseChannel(hexColor[1:3])
	green := parseChannel(hexColor[3:5])
	blue := parseChannel(hexColor[5:7])

	brightness := ((red * 299) + (green * 587) + (blue * 114)) / 1000
	if brightness >= 150 {
		return "#111111"
	}
	return "#FFFFFF"
}

// generateConfigYAML generates YAML configuration using text template
func generateConfigYAML(config *Config) (string, error) {
	tmpl := `# OpenID Connect IdP settings
oidcld:{{if .OIDCLD.Issuer}}
  iss: "{{.OIDCLD.Issuer}}"{{else}}
  # iss: "http://localhost:18888"{{end}}
  pkce_required: {{.OIDCLD.PKCERequired}}
  nonce_required: {{.OIDCLD.NonceRequired}}
  expired_in: {{.OIDCLD.ExpiredIn}}  # Token expiration in seconds
  aud_claim_format: {{.OIDCLD.NormalizedAudienceClaimFormat}}  # string or array for single-audience aud claim serialization
  # Standard scopes (openid, profile, email) are always included
  valid_scopes:  # Optional custom scopes{{range .OIDCLD.ValidScopes}}
    - "{{.}}"{{end}}
  access_filter:
    enabled: {{.OIDCLD.AccessFilter.Enabled}}
    extra_allowed_ips:{{if .OIDCLD.AccessFilter.ExtraAllowedIPs}}{{range .OIDCLD.AccessFilter.ExtraAllowedIPs}}
      - "{{.}}"{{end}}{{else}} []{{end}}
    max_forwarded_hops: {{.OIDCLD.AccessFilter.MaxForwardedHops}}
{{if .OIDCLD.LoginUI}}
  login_ui:{{if .OIDCLD.LoginUI.EnvTitle}}
    env_title: "{{.OIDCLD.LoginUI.EnvTitle}}"{{end}}{{if .OIDCLD.LoginUI.AccentColor}}
    accent_color: "{{.OIDCLD.LoginUI.AccentColor}}"{{end}}{{if .OIDCLD.LoginUI.InfoMarkdownFile}}
    info_markdown_file: "{{.OIDCLD.LoginUI.InfoMarkdownFile}}"{{end}}
{{else}}
  # login_ui:
  #   env_title: "Staging"
  #   accent_color: "#D97A00"
  #   info_markdown_file: "./docs/login-links.staging.md"
{{end}}
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
    - "{{.}}"{{end}}{{end}}{{if .CORS.AllowedMethods}}
  allowed_methods:{{range .CORS.AllowedMethods}}
    - "{{.}}"{{end}}{{end}}{{if .CORS.AllowedHeaders}}
  allowed_headers:{{range .CORS.AllowedHeaders}}
    - "{{.}}"{{end}}{{end}}
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
	case "aud_claim_format":
		if v, ok := value.(string); ok {
			config.OIDCLD.AudienceClaimFormat = normalizeAudienceClaimFormat(v)
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

// ValidateAutocertConfig validates the autocert configuration.
func (c *Config) ValidateAutocertConfig() error {
	if c.Autocert == nil || !c.Autocert.Enabled {
		return nil // Disabled or nil autocert is valid
	}

	if len(c.Autocert.Domains) == 0 {
		return ErrAutocertDomainsRequired
	}

	if c.Autocert.Email == "" {
		return ErrAutocertEmailRequired
	}

	if !c.Autocert.AgreeTOS {
		return ErrAutocertAgreeTOS
	}

	// Set defaults for optional fields
	if c.Autocert.CacheDir == "" {
		c.Autocert.CacheDir = "./autocert-cache"
	}

	// If not set (0) or negative, default to 30 days
	if c.Autocert.RenewalThreshold <= 0 {
		c.Autocert.RenewalThreshold = 1 // Default to 1 day
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
	// If autocert is enabled, disallow explicit TLS cert/key in OIDCLD config to avoid ambiguity.
	if c.OIDCLD.TLSCertFile != "" || c.OIDCLD.TLSKeyFile != "" {
		return ErrAutocertConflict
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
		RenewalThreshold: 1,
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
	var hasOverride bool
	o := &AutocertOverrides{RenewalThreshold: -1}

	if v := os.Getenv("OIDCLD_ACME_DIRECTORY_URL"); v != "" {
		o.ACMEDirectoryURL = v
		hasOverride = true
	}
	if v := os.Getenv("OIDCLD_ACME_EMAIL"); v != "" {
		o.Email = v
		hasOverride = true
	}
	if v := os.Getenv("OIDCLD_ACME_DOMAIN"); v != "" {
		o.Domain = v
		hasOverride = true
	}
	if v := os.Getenv("OIDCLD_ACME_CACHE_DIR"); v != "" {
		o.CacheDir = v
		hasOverride = true
	}
	if v := os.Getenv("OIDCLD_ACME_AGREE_TOS"); v != "" {
		b, _ := strconv.ParseBool(v)
		o.AgreeTOS = b
	}
	if hasOverride {
		applyAutocertOverrides(cfg, o)
	}

	if title, ok := os.LookupEnv("OIDCLD_ENV_TITLE"); ok {
		if cfg.OIDCLD.LoginUI == nil {
			cfg.OIDCLD.LoginUI = &LoginUIConfig{}
		}
		cfg.OIDCLD.LoginUI.EnvTitle = strings.TrimSpace(title)
	}
	if color, ok := os.LookupEnv("OIDCLD_ENV_COLOR"); ok {
		if cfg.OIDCLD.LoginUI == nil {
			cfg.OIDCLD.LoginUI = &LoginUIConfig{}
		}
		cfg.OIDCLD.LoginUI.AccentColor = strings.TrimSpace(color)
	}
	if markdownFile, ok := os.LookupEnv("OIDCLD_ENV_MARKDOWN_FILE"); ok {
		if cfg.OIDCLD.LoginUI == nil {
			cfg.OIDCLD.LoginUI = &LoginUIConfig{}
		}
		cfg.OIDCLD.LoginUI.InfoMarkdownFile = strings.TrimSpace(markdownFile)
	}

	if err := cfg.Normalize(); err != nil {
		return nil, err
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
func applyAutocertOverrides(cfg *Config, overrides *AutocertOverrides) {
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
}
