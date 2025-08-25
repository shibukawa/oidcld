package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
)

// MCPServer represents the Model Context Protocol server.
type MCPServer struct {
	configPath string
	tools      map[string]Tool
	resources  map[string]Resource
}

// NewMCPServer creates a new MCP server instance
func NewMCPServer(configPath string) *MCPServer {
	server := &MCPServer{
		configPath: configPath,
		tools:      make(map[string]Tool),
		resources:  make(map[string]Resource),
	}

	// Register tools
	server.registerTools()

	// Register resources
	server.registerResources()

	return server
}

// Tool represents an MCP tool
type Tool interface {
	Name() string
	Description() string
	InputSchema() map[string]any
	Execute(ctx context.Context, args map[string]any) (any, error)
}

// Resource represents an MCP resource
type Resource interface {
	URI() string
	Name() string
	Description() string
	MimeType() string
	Content(ctx context.Context) ([]byte, error)
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// ServeStdio starts the MCP server using stdin/stdout
func (s *MCPServer) ServeStdio(ctx context.Context) error {
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			var request JSONRPCRequest
			if err := decoder.Decode(&request); err != nil {
				if err == io.EOF {
					return nil
				}
				response := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      nil,
					Error: &JSONRPCError{
						Code:    ParseError,
						Message: "Parse error",
						Data:    err.Error(),
					},
				}
				if err := encoder.Encode(response); err != nil {
					log.Printf("Failed to encode response: %v", err)
				}

				continue
			}

			response := s.handleRequest(ctx, &request)
			if err := encoder.Encode(response); err != nil {
				return fmt.Errorf("failed to encode response: %w", err)
			}
		}
	}
}

// ServeHTTP starts the MCP server using HTTP
func (s *MCPServer) ServeHTTP(ctx context.Context, port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHTTPRequest)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	return server.ListenAndServe()
}

// handleHTTPRequest handles HTTP requests
func (s *MCPServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		response := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error: &JSONRPCError{
				Code:    ParseError,
				Message: "Parse error",
				Data:    err.Error(),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := s.handleRequest(r.Context(), &request)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRequest processes a JSON-RPC request
func (s *MCPServer) handleRequest(ctx context.Context, request *JSONRPCRequest) JSONRPCResponse {
	if request.JSONRPC != "2.0" {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InvalidRequest,
				Message: "Invalid request",
				Data:    "jsonrpc must be '2.0'",
			},
		}
	}

	switch request.Method {
	case "initialize":
		return s.handleInitialize(request)
	case "tools/list":
		return s.handleToolsList(request)
	case "tools/call":
		return s.handleToolsCall(ctx, request)
	case "resources/list":
		return s.handleResourcesList(request)
	case "resources/read":
		return s.handleResourcesRead(ctx, request)
	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    MethodNotFound,
				Message: "Method not found",
				Data:    fmt.Sprintf("Unknown method: %s", request.Method),
			},
		}
	}
}

// handleInitialize handles the initialize request
func (s *MCPServer) handleInitialize(request *JSONRPCRequest) JSONRPCResponse {
	result := map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "oidcld",
			"version": "1.0.0",
		},
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result:  result,
	}
}

// handleToolsList handles the tools/list request
func (s *MCPServer) handleToolsList(request *JSONRPCRequest) JSONRPCResponse {
	tools := make([]map[string]any, 0, len(s.tools))
	for _, tool := range s.tools {
		tools = append(tools, map[string]any{
			"name":        tool.Name(),
			"description": tool.Description(),
			"inputSchema": tool.InputSchema(),
		})
	}

	result := map[string]any{
		"tools": tools,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result:  result,
	}
}

// handleToolsCall handles the tools/call request
func (s *MCPServer) handleToolsCall(ctx context.Context, request *JSONRPCRequest) JSONRPCResponse {
	name, ok := request.Params["name"].(string)
	if !ok {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InvalidParams,
				Message: "Invalid params",
				Data:    "name parameter is required and must be a string",
			},
		}
	}

	tool, exists := s.tools[name]
	if !exists {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InvalidParams,
				Message: "Invalid params",
				Data:    fmt.Sprintf("Unknown tool: %s", name),
			},
		}
	}

	args, ok := request.Params["arguments"].(map[string]any)
	if !ok {
		args = make(map[string]any)
	}

	result, err := tool.Execute(ctx, args)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InternalError,
				Message: "Internal error",
				Data:    err.Error(),
			},
		}
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result: map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": fmt.Sprintf("%v", result),
				},
			},
		},
	}
}

// handleResourcesList handles the resources/list request
func (s *MCPServer) handleResourcesList(request *JSONRPCRequest) JSONRPCResponse {
	resources := make([]map[string]any, 0, len(s.resources))
	for _, resource := range s.resources {
		resources = append(resources, map[string]any{
			"uri":         resource.URI(),
			"name":        resource.Name(),
			"description": resource.Description(),
			"mimeType":    resource.MimeType(),
		})
	}

	result := map[string]any{
		"resources": resources,
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result:  result,
	}
}

// handleResourcesRead handles the resources/read request
func (s *MCPServer) handleResourcesRead(ctx context.Context, request *JSONRPCRequest) JSONRPCResponse {
	uri, ok := request.Params["uri"].(string)
	if !ok {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InvalidParams,
				Message: "Invalid params",
				Data:    "uri parameter is required and must be a string",
			},
		}
	}

	resource, exists := s.resources[uri]
	if !exists {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InvalidParams,
				Message: "Invalid params",
				Data:    fmt.Sprintf("Unknown resource: %s", uri),
			},
		}
	}

	content, err := resource.Content(ctx)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Error: &JSONRPCError{
				Code:    InternalError,
				Message: "Internal error",
				Data:    err.Error(),
			},
		}
	}

	result := map[string]any{
		"contents": []map[string]any{
			{
				"uri":      resource.URI(),
				"mimeType": resource.MimeType(),
				"text":     string(content),
			},
		},
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result:  result,
	}
}

// loadConfig loads the configuration file
func (s *MCPServer) loadConfig() (*config.Config, error) {
	if s.configPath == "" {
		return nil, ErrConfigPathNotSet
	}

	absPath, err := filepath.Abs(s.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config path: %w", err)
	}

	return config.LoadConfig(absPath, false)
}
