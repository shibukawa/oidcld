package mcp

import (
	"errors"
	"slices"
	"testing"
)

func TestToolsWithConfigPathExposeRequiredConfigPathSchema(t *testing.T) {
	server := NewMCPServer("test-config.yaml")
	toolNames := []string{
		"oidcld_init",
		"oidcld_query_config",
		"oidcld_add_user",
		"oidcld_query_users",
		"oidcld_modify_config",
		"oidcld_generate_compose",
	}

	for _, toolName := range toolNames {
		t.Run(toolName, func(t *testing.T) {
			tool := server.tools[toolName]
			schema := tool.InputSchema()

			required, ok := schema["required"].([]string)
			if !ok {
				t.Fatalf("required should be []string, got %T", schema["required"])
			}

			if !containsString(required, "config_path") {
				t.Fatalf("config_path should be required, got %v", required)
			}

			properties, ok := schema["properties"].(map[string]any)
			if !ok {
				t.Fatalf("properties should be map[string]any, got %T", schema["properties"])
			}

			configPathProperty, ok := properties["config_path"].(map[string]any)
			if !ok {
				t.Fatalf("config_path property should be map[string]any, got %T", properties["config_path"])
			}

			if configPathProperty["type"] != "string" {
				t.Fatalf("config_path type should be string, got %v", configPathProperty["type"])
			}
		})
	}
}

func TestToolsWithConfigPathRejectMissingConfigPath(t *testing.T) {
	server := NewMCPServer("test-config.yaml")
	toolNames := []string{
		"oidcld_init",
		"oidcld_query_config",
		"oidcld_add_user",
		"oidcld_query_users",
		"oidcld_modify_config",
		"oidcld_generate_compose",
	}

	for _, toolName := range toolNames {
		t.Run(toolName, func(t *testing.T) {
			tool := server.tools[toolName]
			_, err := tool.Execute(t.Context(), map[string]any{})
			if !errors.Is(err, ErrConfigPathRequired) {
				t.Fatalf("expected ErrConfigPathRequired, got %v", err)
			}
		})
	}
}

func containsString(values []string, target string) bool {
	return slices.Contains(values, target)
}
