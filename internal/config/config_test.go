package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestInitializeConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	tests := []struct {
		name string
		mode Mode
	}{
		{"Standard mode", ModeStandard},
		{"EntraID v1 mode", ModeEntraIDv1},
		{"EntraID v2 mode", ModeEntraIDv2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InitializeConfig(configPath, tt.mode)
			assert.NoError(t, err)

			// Verify file was created
			_, err = os.Stat(configPath)
			assert.NoError(t, err, "Config file should exist")

			// Load and verify configuration
			config, err := LoadConfig(configPath, true)
			assert.NoError(t, err)
			assert.True(t, config != nil, "Config should not be nil")

			// Verify basic structure
			assert.True(t, len(config.Users) > 0, "Users should not be empty")
			_, hasAdmin := config.Users["admin"]
			assert.True(t, hasAdmin, "Should contain admin user")
			_, hasUser := config.Users["user"]
			assert.True(t, hasUser, "Should contain user")
			_, hasManager := config.Users["manager"]
			assert.True(t, hasManager, "Should contain manager")
			_, hasDeveloper := config.Users["developer"]
			assert.True(t, hasDeveloper, "Should contain developer")
			_, hasAnalyst := config.Users["analyst"]
			assert.True(t, hasAnalyst, "Should contain analyst")
			_, hasGuest := config.Users["guest"]
			assert.True(t, hasGuest, "Should contain guest")

			// Clean up for next test
			os.Remove(configPath)
		})
	}
}

func TestGenerateConfigYAML(t *testing.T) {
	config := createDefaultConfig(ModeStandard)

	yamlContent, err := generateConfigYAML(config)
	assert.NoError(t, err)
	assert.True(t, len(yamlContent) > 0, "YAML content should not be empty")

	// Verify structure and comments
	assert.True(t, strings.Contains(yamlContent, "# OpenID Connect IdP settings"), "Should contain main comment")
	assert.True(t, strings.Contains(yamlContent, "# Standard scopes (openid, profile, email) are always included"), "Should contain scope comment")
	assert.True(t, strings.Contains(yamlContent, "aud_claim_format: string"), "Should contain default audience claim format")
	assert.True(t, strings.Contains(yamlContent, "# Access filtering for OIDC and console listeners"), "Should contain access filter comment")
	assert.True(t, strings.Contains(yamlContent, "access_filter:"), "Should contain access filter section")
	assert.True(t, strings.Contains(yamlContent, "console:"), "Should contain console section")
	assert.True(t, strings.Contains(yamlContent, "certificate_authority:"), "Should contain certificate authority section")
	assert.True(t, strings.Contains(yamlContent, "# reverse_proxy:"), "Should contain reverse proxy sample section")
	assert.True(t, strings.Contains(yamlContent, "enabled: true"), "Should contain default access filter enabled state")
	assert.True(t, strings.Contains(yamlContent, "max_forwarded_hops: 0"), "Should contain default forwarded hops")

	// Verify empty line between sections
	assert.True(t, strings.Contains(yamlContent, "# User definitions\nusers:"), "Should have proper section separation")

	// Verify users section
	assert.True(t, strings.Contains(yamlContent, "admin:"), "Should contain admin user")
	assert.True(t, strings.Contains(yamlContent, "user:"), "Should contain user")
	assert.True(t, strings.Contains(yamlContent, "manager:"), "Should contain manager")
	assert.True(t, strings.Contains(yamlContent, "developer:"), "Should contain developer")
	assert.True(t, strings.Contains(yamlContent, "analyst:"), "Should contain analyst")
	assert.True(t, strings.Contains(yamlContent, "guest:"), "Should contain guest")
	assert.True(t, strings.Contains(yamlContent, "# login_ui:"), "Should contain login_ui sample")
	assert.True(t, strings.Contains(yamlContent, "domains:"), "Should contain certificate authority domains")
}

func TestCreateDefaultConfig_DefaultAudienceClaimFormat(t *testing.T) {
	config := createDefaultConfig(ModeStandard)
	assert.Equal(t, AudienceClaimFormatString, config.OIDC.NormalizedAudienceClaimFormat())
	assert.True(t, config.AccessFilter.Enabled)
	assert.True(t, config.Console != nil)
	assert.Equal(t, "18889", config.Console.Port)
	assert.True(t, config.CertificateAuthority != nil)
	assert.Equal(t, []string{"localhost", "*.dev.localhost"}, config.CertificateAuthority.Domains)
	assert.Equal(t, 0, config.AccessFilter.MaxForwardedHops)
	assert.Equal(t, 0, len(config.AccessFilter.ExtraAllowedIPs))
}

func TestNormalizeAllowsCertificateAuthorityWithAutocert(t *testing.T) {
	cfg := &Config{
		OIDC: OIDCConfig{
			Issuer: "https://localhost:18443",
		},
		CertificateAuthority: &CertificateAuthorityConfig{Domains: []string{"localhost", "*.dev.localhost"}},
		Autocert:             &AutocertConfig{Enabled: true},
		Users: map[string]User{
			"admin": {DisplayName: "Administrator"},
		},
	}

	err := cfg.Normalize()
	assert.NoError(t, err)
}

func TestLoadConfig_RejectsLegacyCertificateAuthorityKeys(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "https://localhost:18443"
certificate_authority:
  domain_suffix: "dev.localhost"
users:
  admin:
    display_name: "Administrator"
`), 0644)
	assert.NoError(t, err)

	_, err = LoadConfig(configPath, false)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "certificate_authority.domain_suffix"))
}

func TestApplyInitServerOptionsEnablesAdminConsoleForSelfSignedTLS(t *testing.T) {
	cfg := createDefaultConfig(ModeStandard)
	cfg.Console = nil
	cfg.CertificateAuthority = nil

	cfg.ApplyInitServerOptions(ModeStandard, &InitServerOptions{
		HTTPS:         true,
		SelfSignedTLS: true,
	})

	assert.True(t, cfg.CertificateAuthority != nil)
	assert.True(t, cfg.Console != nil)
}

func TestLoadConfig_NormalizesMissingAccessFilter(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "http://localhost:18888"
users:
  admin:
    display_name: "Administrator"
`), 0644)
	assert.NoError(t, err)

	cfg, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.True(t, cfg.AccessFilter.Enabled)
	assert.Equal(t, 0, cfg.AccessFilter.MaxForwardedHops)
	assert.Equal(t, []string{}, cfg.AccessFilter.ExtraAllowedIPs)
}

func TestLoadConfig_NormalizesExtraAllowedIPs(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`access_filter:
  enabled: true
  extra_allowed_ips:
    - "203.0.113.10"
    - "198.51.100.0/24"
  max_forwarded_hops: 1
oidc:
  iss: "http://localhost:18888"
users:
  admin:
    display_name: "Administrator"
`), 0644)
	assert.NoError(t, err)

	cfg, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.10/32", "198.51.100.0/24"}, cfg.AccessFilter.ExtraAllowedIPs)
	assert.Equal(t, 1, cfg.AccessFilter.MaxForwardedHops)
}

func TestLoadConfig_RejectsInvalidExtraAllowedIPs(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`access_filter:
  extra_allowed_ips:
    - "not-an-ip"
oidc:
  iss: "http://localhost:18888"
users:
  admin:
    display_name: "Administrator"
`), 0644)
	assert.NoError(t, err)

	_, err = LoadConfig(configPath, false)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "extra_allowed_ips"))
}

func TestGenerateConfigYAMLWithEntraID(t *testing.T) {
	config := createDefaultConfig(ModeEntraIDv2)

	yamlContent, err := generateConfigYAML(config)
	assert.NoError(t, err)
	assert.True(t, len(yamlContent) > 0, "YAML content should not be empty")

	// Verify EntraID section is included
	assert.True(t, strings.Contains(yamlContent, "# EntraID/AzureAD compatibility settings"), "Should contain EntraID comment")
	assert.True(t, strings.Contains(yamlContent, "entraid:"), "Should contain entraid section")
	assert.True(t, strings.Contains(yamlContent, "tenant_id:"), "Should contain tenant_id")
	assert.True(t, strings.Contains(yamlContent, "version:"), "Should contain version")
}

func TestLoadConfig_NormalizesReverseProxyStaticDirRelativeToConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "http://localhost:18888"
reverse_proxy:
  hosts:
    - host: "https://app.localhost"
      routes:
        - path: "/"
          static_dir: "./public"
          spa_fallback: true
users:
  admin:
    display_name: "Administrator"
`), 0o644)
	assert.NoError(t, err)

	cfg, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(tempDir, "public"), cfg.ReverseProxy.Hosts[0].Routes[0].ResolvedStaticDir())
}

func TestLoadConfig_RejectsReverseProxyHostWithoutScheme(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "http://localhost:18888"
reverse_proxy:
  hosts:
    - host: "app.localhost"
      routes:
        - path: "/"
          target_url: "http://127.0.0.1:3000"
users:
  admin:
    display_name: "Administrator"
`), 0o644)
	assert.NoError(t, err)

	_, err = LoadConfig(configPath, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "http:// or https://")
}

func TestLoadConfig_RejectsReverseProxyTLSFilesOnHTTPHost(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "http://localhost:18888"
reverse_proxy:
  hosts:
    - host: "http://app.localhost"
      tls_cert_file: "./cert.pem"
      tls_key_file: "./key.pem"
      routes:
        - path: "/"
          target_url: "http://127.0.0.1:3000"
users:
  admin:
    display_name: "Administrator"
`), 0o644)
	assert.NoError(t, err)

	_, err = LoadConfig(configPath, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "require an https host")
}

func TestLoadAndSaveConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Create initial config
	originalConfig := createDefaultConfig(ModeStandard)
	err := SaveConfig(configPath, originalConfig)
	assert.NoError(t, err)

	// Load config
	loadedConfig, err := LoadConfig(configPath, false)
	assert.NoError(t, err)

	// Verify loaded config matches original
	assert.Equal(t, originalConfig.OIDC.PKCERequired, loadedConfig.OIDC.PKCERequired)
	assert.Equal(t, originalConfig.OIDC.RefreshTokenEnabled, loadedConfig.OIDC.RefreshTokenEnabled)
	assert.Equal(t, len(originalConfig.Users), len(loadedConfig.Users))
}

func TestLoadConfig_LoginUIEnvOverridePriority(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "http://localhost:18888"
  login_ui:
    env_title: "Local"
    accent_color: "#123456"
    info_markdown_file: "./docs/local.md"
users:
  admin:
    display_name: "Administrator"
`), 0644)
	assert.NoError(t, err)

	t.Setenv("OIDCLD_ENV_TITLE", "Staging")
	t.Setenv("OIDCLD_ENV_COLOR", "#ABCDEF")
	t.Setenv("OIDCLD_ENV_MARKDOWN_FILE", "./docs/staging.md")

	cfg, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "Staging", cfg.OIDC.LoginUI.EnvTitle)
	assert.Equal(t, "#ABCDEF", cfg.OIDC.LoginUI.AccentColor)
	assert.Equal(t, "./docs/staging.md", cfg.OIDC.LoginUI.InfoMarkdownFile)
	assert.Equal(t, filepath.Join(tempDir, "docs", "staging.md"), cfg.OIDC.LoginUI.resolvedInfoMarkdownFile)
	assert.Equal(t, "#111111", cfg.OIDC.LoginUI.EffectiveTextColor())
}

func TestNormalizeLoginUIGeneratesDeterministicAccentColor(t *testing.T) {
	cfg := &Config{
		OIDC: OIDCConfig{
			Issuer: "http://localhost:18888",
			LoginUI: &LoginUIConfig{
				EnvTitle: "Staging",
			},
		},
		Users: map[string]User{
			"admin": {DisplayName: "Administrator"},
		},
	}

	err := cfg.Normalize()
	assert.NoError(t, err)
	assert.NotEqual(t, "", cfg.OIDC.LoginUI.EffectiveAccentColor())
	assert.Equal(t, generateAccentColorFromTitle("Staging"), cfg.OIDC.LoginUI.EffectiveAccentColor())

	secondCfg := &Config{
		OIDC: OIDCConfig{
			Issuer: "http://localhost:18888",
			LoginUI: &LoginUIConfig{
				EnvTitle: "Staging",
			},
		},
		Users: map[string]User{
			"admin": {DisplayName: "Administrator"},
		},
	}
	err = secondCfg.Normalize()
	assert.NoError(t, err)
	assert.Equal(t, cfg.OIDC.LoginUI.EffectiveAccentColor(), secondCfg.OIDC.LoginUI.EffectiveAccentColor())
}

func TestNormalizeLoginUIKeepsExplicitAccentColor(t *testing.T) {
	cfg := &Config{
		OIDC: OIDCConfig{
			Issuer: "http://localhost:18888",
			LoginUI: &LoginUIConfig{
				EnvTitle:    "Staging",
				AccentColor: "#d97a00",
			},
		},
		Users: map[string]User{
			"admin": {DisplayName: "Administrator"},
		},
	}

	err := cfg.Normalize()
	assert.NoError(t, err)
	assert.Equal(t, "#D97A00", cfg.OIDC.LoginUI.AccentColor)
	assert.Equal(t, "#D97A00", cfg.OIDC.LoginUI.EffectiveAccentColor())
}

func TestLoadConfig_LoginUIResolvesMarkdownPathRelativeToConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configPath, []byte(`oidc:
  iss: "http://localhost:18888"
  login_ui:
    env_title: "Docs"
    info_markdown_file: "./notes/login.md"
users:
  admin:
    display_name: "Administrator"
`), 0644)
	assert.NoError(t, err)

	cfg, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "./notes/login.md", cfg.OIDC.LoginUI.InfoMarkdownFile)
	assert.Equal(t, filepath.Join(tempDir, "notes", "login.md"), cfg.OIDC.LoginUI.EffectiveInfoMarkdownFile())
}

func TestAddUser(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Initialize config
	err := InitializeConfig(configPath, ModeStandard)
	assert.NoError(t, err)

	// Add new user
	newUser := User{
		DisplayName:      "New Test User",
		ExtraValidScopes: []string{"read", "write"},
		ExtraClaims: map[string]any{
			"email": "newuser@example.com",
			"role":  "tester",
		},
	}

	err = AddUser(configPath, "newuser", newUser)
	assert.NoError(t, err)

	// Verify user was added
	config, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	_, hasNewUser := config.Users["newuser"]
	assert.True(t, hasNewUser, "Should contain new user")
	assert.Equal(t, "New Test User", config.Users["newuser"].DisplayName)
}

func TestRemoveUser(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Initialize config
	err := InitializeConfig(configPath, ModeStandard)
	assert.NoError(t, err)

	// Remove user
	err = RemoveUser(configPath, "guest")
	assert.NoError(t, err)

	// Verify user was removed
	config, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	_, hasGuest := config.Users["guest"]
	assert.False(t, hasGuest, "Should not contain guest")
	_, hasAdmin := config.Users["admin"]
	assert.True(t, hasAdmin, "Should still contain admin user")
}

func TestModifyConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Initialize config
	err := InitializeConfig(configPath, ModeStandard)
	assert.NoError(t, err)

	// Modify config
	updates := map[string]any{
		"pkce_required":         false,
		"nonce_required":        true,
		"expired_in":            7200,
		"aud_claim_format":      "array",
		"refresh_token_enabled": false,
	}

	err = ModifyConfig(configPath, updates)
	assert.NoError(t, err)

	// Verify changes
	config, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.False(t, config.OIDC.PKCERequired)
	assert.True(t, config.OIDC.NonceRequired)
	assert.Equal(t, 7200, config.OIDC.ExpiredIn)
	assert.Equal(t, AudienceClaimFormatArray, config.OIDC.NormalizedAudienceClaimFormat())
	assert.False(t, config.OIDC.RefreshTokenEnabled)
}

func TestDefaultServePort(t *testing.T) {
	assert.Equal(t, DefaultHTTPPort, DefaultServePort(false))
	assert.Equal(t, DefaultHTTPSPort, DefaultServePort(true))
}

func TestConfigYAMLFormatting(t *testing.T) {
	config := createDefaultConfig(ModeStandard)
	yamlContent, err := generateConfigYAML(config)
	assert.NoError(t, err)

	lines := strings.Split(yamlContent, "\n")

	// Find the line with "# User definitions"
	var userDefLineIndex int
	for i, line := range lines {
		if strings.Contains(line, "# User definitions") {
			userDefLineIndex = i
			break
		}
	}

	// Verify there's an empty line before "# User definitions"
	assert.True(t, userDefLineIndex > 0, "User definitions section should not be at the beginning")
	assert.Equal(t, "", strings.TrimSpace(lines[userDefLineIndex-1]), "Should have empty line before user definitions")
}

func TestConfigModes(t *testing.T) {
	tests := []struct {
		mode           Mode
		expectedIssuer string
		expectEntraID  bool
	}{
		{ModeStandard, "http://localhost:18888", false},
		{ModeEntraIDv1, "https://login.microsoftonline.com/common", true},
		{ModeEntraIDv2, "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			config := createDefaultConfig(tt.mode)

			assert.Equal(t, tt.expectedIssuer, config.OIDC.Issuer)

			if tt.expectEntraID {
				assert.True(t, config.EntraID != nil, "EntraID config should not be nil")
				assert.True(t, len(config.EntraID.TenantID) > 0, "TenantID should not be empty")
				assert.True(t, len(config.EntraID.Version) > 0, "Version should not be empty")
			} else {
				assert.True(t, config.EntraID == nil, "EntraID config should be nil")
			}
		})
	}
}

func TestPrepareForServeSyncsLocalhostIssuerPort(t *testing.T) {
	cfg := createDefaultConfig(ModeStandard)

	useHTTPS, msg := cfg.PrepareForServe(&ServeOptions{
		Port: "19000",
	})

	assert.False(t, useHTTPS)
	assert.Equal(t, "", msg)
	assert.Equal(t, "http://localhost:19000", cfg.OIDC.Issuer)
}

func TestPrepareForServeKeepsNonLocalhostIssuer(t *testing.T) {
	cfg := createDefaultConfig(ModeEntraIDv2)
	originalIssuer := cfg.OIDC.Issuer

	useHTTPS, _ := cfg.PrepareForServe(&ServeOptions{
		Port: "19000",
	})

	assert.True(t, useHTTPS)
	assert.Equal(t, originalIssuer, cfg.OIDC.Issuer)
}

func TestPrepareForServeSyncsLocalhostHTTPSIssuerPort(t *testing.T) {
	cfg := createDefaultConfig(ModeStandard)
	cfg.OIDC.Issuer = "https://localhost:8443"

	useHTTPS, msg := cfg.PrepareForServe(&ServeOptions{
		Port: "19000",
	})

	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)
	assert.Equal(t, "https://localhost:19000", cfg.OIDC.Issuer)
}

func TestPrepareForServeSyncsLoopbackIPv4IssuerPort(t *testing.T) {
	cfg := createDefaultConfig(ModeStandard)
	cfg.OIDC.Issuer = "http://127.0.0.1:18888"

	useHTTPS, _ := cfg.PrepareForServe(&ServeOptions{
		Port: "19000",
	})

	assert.False(t, useHTTPS)
	assert.Equal(t, "http://127.0.0.1:19000", cfg.OIDC.Issuer)
}

func TestPrepareForServeNormalizesEntraIDv2IssuerPath(t *testing.T) {
	cfg := createDefaultConfig(ModeEntraIDv2)
	cfg.OIDC.Issuer = "https://oidc.localhost:8443"

	useHTTPS, msg := cfg.PrepareForServe(&ServeOptions{
		Port: "8443",
	})

	assert.True(t, useHTTPS)
	assert.Equal(t, "", msg)
	assert.Equal(t, "https://oidc.localhost:8443/12345678-1234-1234-1234-123456789abc/v2.0", cfg.OIDC.Issuer)
}
