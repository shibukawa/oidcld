// Package mcp provides Model Context Protocol server implementation
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Static errors for MCP operations.
var (
	ErrConfigPathNotSet    = errors.New("configuration path not set")
	ErrConfigPathRequired  = errors.New("config_path is required and must be a string")
	ErrInvalidMode         = errors.New("invalid mode")
	ErrUserIDRequired      = errors.New("user_id is required and must be a string")
	ErrDisplayNameRequired = errors.New("display_name is required and must be a string")
	ErrUserAlreadyExists   = errors.New("user already exists")
	ErrUpdatesRequired     = errors.New("updates is required and must be an object")
)

// registerResources registers all available MCP resources.
func (s *MCPServer) registerResources() {
	s.resources["config://current"] = &CurrentConfigResource{server: s}
	s.resources["users://list"] = &UsersListResource{server: s}
	s.resources["compose://template"] = &ComposeTemplateResource{server: s}
}

// CurrentConfigResource implements the config://current resource.
type CurrentConfigResource struct {
	server *MCPServer
}

func (r *CurrentConfigResource) URI() string {
	return "config://current"
}

func (r *CurrentConfigResource) Name() string {
	return "Current Configuration"
}

func (r *CurrentConfigResource) Description() string {
	return "Current OpenID Connect configuration"
}

func (r *CurrentConfigResource) MimeType() string {
	return "application/yaml"
}

func (r *CurrentConfigResource) Content(_ context.Context) ([]byte, error) {
	if r.server.configPath == "" {
		return nil, ErrConfigPathNotSet
	}

	// Read raw YAML content
	content, err := os.ReadFile(r.server.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return content, nil
}

// UsersListResource implements the users://list resource.
type UsersListResource struct {
	server *MCPServer
}

func (r *UsersListResource) URI() string {
	return "users://list"
}

func (r *UsersListResource) Name() string {
	return "User List"
}

func (r *UsersListResource) Description() string {
	return "List of all configured users"
}

func (r *UsersListResource) MimeType() string {
	return "application/json"
}

func (r *UsersListResource) Content(_ context.Context) ([]byte, error) {
	cfg, err := r.server.loadConfig()
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

	result := map[string]any{
		"users": users,
		"count": len(users),
	}

	content, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal users: %w", err)
	}

	return content, nil
}

// ComposeTemplateResource implements the compose://template resource.
type ComposeTemplateResource struct {
	server *MCPServer
}

func (r *ComposeTemplateResource) URI() string {
	return "compose://template"
}

func (r *ComposeTemplateResource) Name() string {
	return "Docker Compose Template"
}

func (r *ComposeTemplateResource) Description() string {
	return "Docker Compose template for OpenID Connect server"
}

func (r *ComposeTemplateResource) MimeType() string {
	return "application/yaml"
}

func (r *ComposeTemplateResource) Content(_ context.Context) ([]byte, error) {
	template := `services:
  oidcld:
    image: ghcr.io/shibukawa/oidcld:latest
    container_name: oidcld
    ports:
      - "18888:18888"
    volumes:
      - ./oidcld.yaml:/app/oidcld.yaml:ro
    environment:
      - PORT=18888
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:18888/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s
    networks:
      - oidc-network

  # Example application service
  example-app:
    image: nginx:alpine
    container_name: example-app
    ports:
      - "8080:80"
    depends_on:
      oidcld:
        condition: service_healthy
    networks:
      - oidc-network
    volumes:
      - ./html:/usr/share/nginx/html:ro

networks:
  oidc-network:
    driver: bridge

volumes:
  oidc-data:
`

	return []byte(template), nil
}
