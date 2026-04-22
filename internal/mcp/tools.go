package mcp

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"

	"github.com/shibukawa/oidcld/internal/config"
)

// registerTools registers all available MCP tools
func (s *MCPServer) registerTools() {
	s.tools["oidcld_init"] = &InitTool{server: s}
	s.tools["oidcld_query_config"] = &QueryConfigTool{server: s}
	s.tools["oidcld_add_user"] = &AddUserTool{server: s}
	s.tools["oidcld_query_users"] = &QueryUsersTool{server: s}
	s.tools["oidcld_modify_config"] = &ModifyConfigTool{server: s}
	s.tools["oidcld_generate_compose"] = &GenerateComposeTool{server: s}
}

func configPathPropertySchema() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Path to configuration file",
	}
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": properties,
		"required":   required,
	}
}

func configPathObjectSchema(properties map[string]any, required ...string) map[string]any {
	mergedProperties := map[string]any{
		"config_path": configPathPropertySchema(),
	}
	maps.Copy(mergedProperties, properties)

	mergedRequired := append([]string{"config_path"}, required...)
	return objectSchema(mergedProperties, mergedRequired...)
}

func requiredStringArg(args map[string]any, key string, missingErr error) (string, error) {
	value, ok := args[key].(string)
	if !ok {
		return "", missingErr
	}
	return value, nil
}

// InitTool implements the oidcld_init tool
type InitTool struct {
	server *MCPServer
}

func (t *InitTool) Name() string {
	return "oidcld_init"
}

func (t *InitTool) Description() string {
	return "Initialize OpenID Connect configuration"
}

func (t *InitTool) InputSchema() map[string]any {
	return configPathObjectSchema(map[string]any{
		"mode": map[string]any{
			"type":        "string",
			"description": "Configuration mode",
			"enum":        []string{"standard", "entraid-v1", "entraid-v2"},
			"default":     "standard",
		},
		"tenant_id": map[string]any{
			"type":        "string",
			"description": "Tenant ID for EntraID templates",
		},
		"port": map[string]any{
			"type":        "string",
			"description": "Port number for issuer URL",
			"default":     "8080",
		},
	})
}

func (t *InitTool) Execute(ctx context.Context, args map[string]any) (any, error) {
	configPath, err := requiredStringArg(args, "config_path", ErrConfigPathRequired)
	if err != nil {
		return nil, err
	}

	mode, _ := args["mode"].(string)
	if mode == "" {
		mode = "standard"
	}

	tenantID, _ := args["tenant_id"].(string)
	port, _ := args["port"].(string)
	if port == "" {
		port = "8080"
	}

	// Convert string mode to Mode
	var configMode config.Mode
	switch mode {
	case "standard":
		configMode = config.ModeStandard
	case "entraid-v1":
		configMode = config.ModeEntraIDv1
	case "entraid-v2":
		configMode = config.ModeEntraIDv2
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidMode, mode)
	}

	// Create configuration based on mode
	cfg, err := config.CreateDefaultConfig(configMode)
	if err != nil {
		return nil, fmt.Errorf("failed to create default config: %w", err)
	}

	// Set tenant ID if provided
	if tenantID != "" && (mode == "entraid-v1" || mode == "entraid-v2") {
		if cfg.EntraID == nil {
			cfg.EntraID = &config.EntraIDConfig{}
		}
		cfg.EntraID.TenantID = tenantID
	}

	// Set issuer URL with port
	cfg.OIDC.Issuer = fmt.Sprintf("http://localhost:%s", port)

	// Save configuration
	absPath, err := t.server.setConfigPath(configPath)
	if err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}

	if err := config.SaveConfig(absPath, cfg); err != nil {
		return nil, fmt.Errorf("failed to save config: %w", err)
	}

	return map[string]any{
		"status":      "success",
		"config_path": absPath,
		"mode":        mode,
		"message":     "Configuration initialized successfully",
	}, nil
}

// QueryConfigTool implements the oidcld_query_config tool
type QueryConfigTool struct {
	server *MCPServer
}

func (t *QueryConfigTool) Name() string {
	return "oidcld_query_config"
}

func (t *QueryConfigTool) Description() string {
	return "Query current OpenID Connect configuration"
}

func (t *QueryConfigTool) InputSchema() map[string]any {
	return configPathObjectSchema(map[string]any{})
}

func (t *QueryConfigTool) Execute(ctx context.Context, args map[string]any) (any, error) {
	configPath, err := requiredStringArg(args, "config_path", ErrConfigPathRequired)
	if err != nil {
		return nil, err
	}

	cfg, err := t.server.loadConfigAtPath(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Mask sensitive information
	result := map[string]any{
		"oidcld": map[string]any{
			"issuer":                       cfg.OIDC.Issuer,
			"pkce_required":                cfg.OIDC.PKCERequired,
			"nonce_required":               cfg.OIDC.NonceRequired,
			"expired_in":                   cfg.OIDC.ExpiredIn,
			"valid_scopes":                 cfg.OIDC.ValidScopes,
			"refresh_token_enabled":        cfg.OIDC.RefreshTokenEnabled,
			"refresh_token_expiry":         cfg.OIDC.RefreshTokenExpiry,
			"end_session_enabled":          cfg.OIDC.EndSessionEnabled,
			"end_session_endpoint_visible": cfg.OIDC.EndSessionEndpointVisible,
		},
		"users": cfg.Users,
	}

	if cfg.EntraID != nil {
		result["entraid"] = map[string]any{
			"tenant_id": cfg.EntraID.TenantID,
			"version":   cfg.EntraID.Version,
		}
	}

	return result, nil
}

// AddUserTool implements the oidcld_add_user tool
type AddUserTool struct {
	server *MCPServer
}

func (t *AddUserTool) Name() string {
	return "oidcld_add_user"
}

func (t *AddUserTool) Description() string {
	return "Add a new test user"
}

func (t *AddUserTool) InputSchema() map[string]any {
	return configPathObjectSchema(map[string]any{
		"user_id": map[string]any{
			"type":        "string",
			"description": "User ID",
		},
		"display_name": map[string]any{
			"type":        "string",
			"description": "Display name",
		},
		"extra_valid_scopes": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "string",
			},
			"description": "Additional valid scopes for the user",
		},
		"extra_claims": map[string]any{
			"type":        "object",
			"description": "Additional claims for the user",
		},
	}, "user_id", "display_name")
}

func (t *AddUserTool) Execute(ctx context.Context, args map[string]any) (any, error) {
	configPath, err := requiredStringArg(args, "config_path", ErrConfigPathRequired)
	if err != nil {
		return nil, err
	}

	userID, err := requiredStringArg(args, "user_id", ErrUserIDRequired)
	if err != nil {
		return nil, err
	}

	displayName, err := requiredStringArg(args, "display_name", ErrDisplayNameRequired)
	if err != nil {
		return nil, err
	}

	cfg, err := t.server.loadConfigAtPath(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Check if user already exists
	if _, exists := cfg.Users[userID]; exists {
		return nil, fmt.Errorf("%w: %s", ErrUserAlreadyExists, userID)
	}

	// Create new user
	user := config.User{
		DisplayName: displayName,
	}

	// Add extra valid scopes
	if extraScopes, ok := args["extra_valid_scopes"].([]any); ok {
		for _, scope := range extraScopes {
			if scopeStr, ok := scope.(string); ok {
				user.ExtraValidScopes = append(user.ExtraValidScopes, scopeStr)
			}
		}
	}

	// Add extra claims
	if extraClaims, ok := args["extra_claims"].(map[string]any); ok {
		user.ExtraClaims = extraClaims
	}

	// Add user to configuration
	if cfg.Users == nil {
		cfg.Users = make(map[string]config.User)
	}
	cfg.Users[userID] = user

	// Save configuration
	if err := config.SaveConfig(t.server.configPath, cfg); err != nil {
		return nil, fmt.Errorf("failed to save config: %w", err)
	}

	return map[string]any{
		"status":       "success",
		"user_id":      userID,
		"display_name": displayName,
		"message":      fmt.Sprintf("User %s added successfully", userID),
	}, nil
}

// QueryUsersTool implements the oidcld_query_users tool
type QueryUsersTool struct {
	server *MCPServer
}

func (t *QueryUsersTool) Name() string {
	return "oidcld_query_users"
}

func (t *QueryUsersTool) Description() string {
	return "List all configured users"
}

func (t *QueryUsersTool) InputSchema() map[string]any {
	return configPathObjectSchema(map[string]any{})
}

func (t *QueryUsersTool) Execute(ctx context.Context, args map[string]any) (any, error) {
	configPath, err := requiredStringArg(args, "config_path", ErrConfigPathRequired)
	if err != nil {
		return nil, err
	}

	cfg, err := t.server.loadConfigAtPath(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	users := make([]map[string]any, 0, len(cfg.Users))
	for userID, user := range cfg.Users {
		users = append(users, map[string]any{
			"user_id":            userID,
			"display_name":       user.DisplayName,
			"extra_valid_scopes": user.ExtraValidScopes,
			"extra_claims":       user.ExtraClaims,
		})
	}

	return map[string]any{
		"users": users,
		"count": len(users),
	}, nil
}

// ModifyConfigTool implements the oidcld_modify_config tool
type ModifyConfigTool struct {
	server *MCPServer
}

func (t *ModifyConfigTool) Name() string {
	return "oidcld_modify_config"
}

func (t *ModifyConfigTool) Description() string {
	return "Modify OpenID Connect configuration settings"
}

func (t *ModifyConfigTool) InputSchema() map[string]any {
	return configPathObjectSchema(map[string]any{
		"updates": map[string]any{
			"type":        "object",
			"description": "Configuration updates to apply",
		},
	}, "updates")
}

func (t *ModifyConfigTool) Execute(ctx context.Context, args map[string]any) (any, error) {
	configPath, err := requiredStringArg(args, "config_path", ErrConfigPathRequired)
	if err != nil {
		return nil, err
	}

	updates, ok := args["updates"].(map[string]any)
	if !ok {
		return nil, ErrUpdatesRequired
	}

	cfg, err := t.server.loadConfigAtPath(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Apply updates (simplified implementation)
	if oidcldUpdates, ok := updates["oidcld"].(map[string]any); ok {
		if pkceRequired, ok := oidcldUpdates["pkce_required"].(bool); ok {
			cfg.OIDC.PKCERequired = pkceRequired
		}

		if nonceRequired, ok := oidcldUpdates["nonce_required"].(bool); ok {
			cfg.OIDC.NonceRequired = nonceRequired
		}

		if expiredIn, ok := oidcldUpdates["expired_in"].(float64); ok {
			cfg.OIDC.ExpiredIn = int(expiredIn)
		}
	}

	// Save configuration
	if err := config.SaveConfig(t.server.configPath, cfg); err != nil {
		return nil, fmt.Errorf("failed to save config: %w", err)
	}

	return map[string]any{
		"status":  "success",
		"message": "Configuration updated successfully",
	}, nil
}

// GenerateComposeTool implements the oidcld_generate_compose tool
type GenerateComposeTool struct {
	server *MCPServer
}

func (t *GenerateComposeTool) Name() string {
	return "oidcld_generate_compose"
}

func (t *GenerateComposeTool) Description() string {
	return "Generate Docker Compose configuration"
}

func (t *GenerateComposeTool) InputSchema() map[string]any {
	return configPathObjectSchema(map[string]any{
		"compose_path": map[string]any{
			"type":        "string",
			"description": "Path to output Docker Compose file",
			"default":     "compose.yaml",
		},
	})
}

func (t *GenerateComposeTool) Execute(ctx context.Context, args map[string]any) (any, error) {
	configPath, err := requiredStringArg(args, "config_path", ErrConfigPathRequired)
	if err != nil {
		return nil, err
	}

	composePath, _ := args["compose_path"].(string)
	if composePath == "" {
		composePath = "compose.yaml"
	}

	if _, err := t.server.setConfigPath(configPath); err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}

	// Generate Docker Compose template
	composeTemplate := `services:
  oidcld:
    image: ghcr.io/shibukawa/oidcld:latest
    container_name: oidcld
    ports:
      - "80:80"
      - "8888:8888"
    volumes:
      - ./` + filepath.Base(configPath) + `:/app/oidcld.yaml:ro
    environment:
      - OIDCLD_CONTAINER=1
      - CONSOLE_PORT=8888
    healthcheck:
      test: ["CMD", "/usr/local/bin/oidcld", "health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
    networks:
      - oidc-network

networks:
  oidc-network:
    driver: bridge
`

	// Write compose file
	if err := os.WriteFile(composePath, []byte(composeTemplate), 0644); err != nil {
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	return map[string]any{
		"status":       "success",
		"compose_path": composePath,
		"config_path":  configPath,
		"message":      "Docker Compose configuration generated successfully",
	}, nil
}
