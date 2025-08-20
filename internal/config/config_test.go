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
			_, hasTestUser := config.Users["testuser"]
			assert.True(t, hasTestUser, "Should contain testuser")

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
	assert.True(t, strings.Contains(yamlContent, "# private_key_path:"), "Should contain private key comment")
	assert.True(t, strings.Contains(yamlContent, "# public_key_path:"), "Should contain public key comment")
	assert.True(t, strings.Contains(yamlContent, "# algorithm:"), "Should contain algorithm comment")

	// Verify empty line between sections
	assert.True(t, strings.Contains(yamlContent, "# User definitions\nusers:"), "Should have proper section separation")

	// Verify users section
	assert.True(t, strings.Contains(yamlContent, "admin:"), "Should contain admin user")
	assert.True(t, strings.Contains(yamlContent, "user:"), "Should contain user")
	assert.True(t, strings.Contains(yamlContent, "testuser:"), "Should contain testuser")
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
	assert.Equal(t, originalConfig.OIDCLD.PKCERequired, loadedConfig.OIDCLD.PKCERequired)
	assert.Equal(t, originalConfig.OIDCLD.RefreshTokenEnabled, loadedConfig.OIDCLD.RefreshTokenEnabled)
	assert.Equal(t, len(originalConfig.Users), len(loadedConfig.Users))
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
	err = RemoveUser(configPath, "testuser")
	assert.NoError(t, err)

	// Verify user was removed
	config, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	_, hasTestUser := config.Users["testuser"]
	assert.False(t, hasTestUser, "Should not contain testuser")
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
		"refresh_token_enabled": false,
	}

	err = ModifyConfig(configPath, updates)
	assert.NoError(t, err)

	// Verify changes
	config, err := LoadConfig(configPath, false)
	assert.NoError(t, err)
	assert.False(t, config.OIDCLD.PKCERequired)
	assert.True(t, config.OIDCLD.NonceRequired)
	assert.Equal(t, 7200, config.OIDCLD.ExpiredIn)
	assert.False(t, config.OIDCLD.RefreshTokenEnabled)
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

	// Verify comments are present for optional fields
	yamlStr := strings.Join(lines, "\n")
	assert.True(t, strings.Contains(yamlStr, "# algorithm:"), "Should contain algorithm comment")
	assert.True(t, strings.Contains(yamlStr, "# private_key_path:"), "Should contain private key comment")
	assert.True(t, strings.Contains(yamlStr, "# public_key_path:"), "Should contain public key comment")
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

			assert.Equal(t, tt.expectedIssuer, config.OIDCLD.Issuer)

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
