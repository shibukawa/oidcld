package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shibukawa/oidcld/internal/config"
)

func TestMCPServer_Initialize(t *testing.T) {
	server := NewMCPServer("test-config.yaml")

	request := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  map[string]any{},
	}

	response := server.handleRequest(t.Context(), request)

	if response.Error != nil {
		t.Fatalf("Expected no error, got: %v", response.Error)
	}

	result, ok := response.Result.(map[string]any)
	if !ok {
		t.Fatal("Expected result to be a map")
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("Expected protocol version 2024-11-05, got: %v", result["protocolVersion"])
	}

	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("Expected serverInfo to be a map")
	}

	if serverInfo["name"] != "oidcld" {
		t.Errorf("Expected server name oidcld, got: %v", serverInfo["name"])
	}
}

func TestMCPServer_ToolsList(t *testing.T) {
	server := NewMCPServer("test-config.yaml")

	request := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
		Params:  map[string]any{},
	}

	response := server.handleRequest(t.Context(), request)

	if response.Error != nil {
		t.Fatalf("Expected no error, got: %v", response.Error)
	}

	result, ok := response.Result.(map[string]any)
	if !ok {
		t.Fatal("Expected result to be a map")
	}

	tools, ok := result["tools"].([]map[string]any)
	if !ok {
		t.Fatal("Expected tools to be a slice of maps")
	}

	expectedTools := []string{
		"oidcld_init",
		"oidcld_query_config",
		"oidcld_add_user",
		"oidcld_query_users",
		"oidcld_modify_config",
		"oidcld_generate_compose",
	}

	if len(tools) != len(expectedTools) {
		t.Errorf("Expected %d tools, got %d", len(expectedTools), len(tools))
	}

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		name, ok := tool["name"].(string)
		if !ok {
			t.Fatal("Expected tool name to be a string")
		}
		toolNames[name] = true
	}

	for _, expectedTool := range expectedTools {
		if !toolNames[expectedTool] {
			t.Errorf("Expected tool %s not found", expectedTool)
		}
	}
}

func TestMCPServer_ResourcesList(t *testing.T) {
	server := NewMCPServer("test-config.yaml")

	request := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "resources/list",
		Params:  map[string]any{},
	}

	response := server.handleRequest(t.Context(), request)

	if response.Error != nil {
		t.Fatalf("Expected no error, got: %v", response.Error)
	}

	result, ok := response.Result.(map[string]any)
	if !ok {
		t.Fatal("Expected result to be a map")
	}

	resources, ok := result["resources"].([]map[string]any)
	if !ok {
		t.Fatal("Expected resources to be a slice of maps")
	}

	expectedResources := []string{
		"config://current",
		"users://list",
		"compose://template",
	}

	if len(resources) != len(expectedResources) {
		t.Errorf("Expected %d resources, got %d", len(expectedResources), len(resources))
	}

	resourceURIs := make(map[string]bool)
	for _, resource := range resources {
		uri, ok := resource["uri"].(string)
		if !ok {
			t.Fatal("Expected resource uri to be a string")
		}
		resourceURIs[uri] = true
	}

	for _, expectedResource := range expectedResources {
		if !resourceURIs[expectedResource] {
			t.Errorf("Expected resource %s not found", expectedResource)
		}
	}
}

func TestMCPServer_InitTool(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-config.yaml")

	server := NewMCPServer(configPath)

	request := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]any{
			"name": "oidcld_init",
			"arguments": map[string]any{
				"config_path": configPath,
				"mode":        "standard",
				"port":        "18888",
			},
		},
	}

	response := server.handleRequest(t.Context(), request)

	if response.Error != nil {
		t.Fatalf("Expected no error, got: %v", response.Error)
	}

	// Check if config file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Expected config file to be created")
	}

	// Verify config content
	cfg, err := config.LoadConfig(configPath, false)
	if err != nil {
		t.Fatalf("Failed to load created config: %v", err)
	}

	if cfg.OIDCLD.Issuer != "http://localhost:18888" {
		t.Errorf("Expected issuer http://localhost:18888, got: %s", cfg.OIDCLD.Issuer)
	}
}

func TestMCPServer_ErrorHandling(t *testing.T) {
	server := NewMCPServer("test-config.yaml")

	tests := []struct {
		name     string
		request  *JSONRPCRequest
		wantCode int
	}{
		{
			name: "Invalid JSON-RPC version",
			request: &JSONRPCRequest{
				JSONRPC: "1.0",
				ID:      1,
				Method:  "initialize",
			},
			wantCode: InvalidRequest,
		},
		{
			name: "Unknown method",
			request: &JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "unknown/method",
			},
			wantCode: MethodNotFound,
		},
		{
			name: "Invalid tool name",
			request: &JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params: map[string]any{
					"name": "unknown_tool",
				},
			},
			wantCode: InvalidParams,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := server.handleRequest(t.Context(), tt.request)

			if response.Error == nil {
				t.Fatal("Expected error, got none")
			}

			if response.Error.Code != tt.wantCode {
				t.Errorf("Expected error code %d, got %d", tt.wantCode, response.Error.Code)
			}
		})
	}
}
