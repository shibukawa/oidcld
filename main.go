// Package main provides the OIDCLD command-line interface
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/shibukawa/oidcld/internal/mcp"
)

// Static errors for main.
var (
	ErrInvalidTemplateChoice    = errors.New("invalid template choice")
	ErrInvalidPortNumber        = errors.New("invalid port number")
	ErrInvalidCertificateChoice = errors.New("invalid certificate choice")
	ErrOperationCancelled       = errors.New("operation cancelled by user")
	ErrConfigFileNotExist       = errors.New("configuration file does not exist")
	ErrFilesExist               = errors.New("files already exist and would be overwritten")
	ErrMkcertNotInstalled       = errors.New("mkcert is not installed")
	ErrHealthCheckFailed        = errors.New("health check failed")
)

// cli is the main command-line interface structure.
var cli struct {
	Init   InitCmd   `cmd:"" help:"Initialize configuration from template"`
	Serve  ServeCmd  `cmd:"" help:"Start OpenID Connect server" default:"1"`
	MCP    MCPCmd    `cmd:"" help:"Start MCP (Model Context Protocol) server"`
	Health HealthCmd `cmd:"" help:"Check server health"`
}

// MCPCmd represents the command to start MCP server
type MCPCmd struct {
	Port   int    `help:"Port to listen on for HTTP mode" default:"3001"`
	Config string `short:"c" help:"Configuration file path" default:"oidcld.yaml"`
}

// Run executes the MCP server command
func (cmd *MCPCmd) Run() error {
	// Create MCP server
	mcpServer := mcp.NewMCPServer(cmd.Config)

	// Create context
	ctx := context.Background()

	// Check if port is specified (HTTP mode) or use stdin/stdout
	if cmd.Port != 3001 || len(os.Args) > 2 {
		// HTTP mode
		color.Cyan("🌐 Starting MCP HTTP server on port %d", cmd.Port)
		return mcpServer.ServeHTTP(ctx, fmt.Sprintf("%d", cmd.Port))
	}

	// Stdin/stdout mode (default)
	color.Cyan("🔌 Starting MCP server in stdin/stdout mode")
	return mcpServer.ServeStdio(ctx)
}

// HealthCmd represents the command to check server health
type HealthCmd struct {
	URL     string        `help:"Server URL to check (auto-detects protocol/port if not specified)" default:""`
	Port    string        `help:"Port to check (overrides URL port)" default:""`
	Config  string        `short:"c" help:"Configuration file path for auto-detection" default:"oidcld.yaml"`
	Timeout time.Duration `help:"Request timeout" default:"10s"`
}

// Run executes the health check command
func (cmd *HealthCmd) Run() error {
	// Auto-detect URL if not provided
	healthURL, err := cmd.buildHealthURL()
	if err != nil {
		return fmt.Errorf("failed to build health URL: %w", err)
	}

	// Create HTTP client with timeout and skip TLS verification for testing
	client := &http.Client{
		Timeout: cmd.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	color.Cyan("🔍 Checking server health at %s", healthURL)

	// Create request with context for timeout
	ctx, cancel := context.WithTimeout(context.Background(), cmd.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		color.Red("❌ Failed to connect to server: %v", err)
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			color.Yellow("⚠️  Warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusOK {
		color.Green("✅ Server is healthy")
		return nil
	}
	color.Red("❌ Server returned status: %d", resp.StatusCode)
	return fmt.Errorf("%w: status %d", ErrHealthCheckFailed, resp.StatusCode)
}

// buildHealthURL constructs the health check URL with auto-detection
func (cmd *HealthCmd) buildHealthURL() (string, error) {
	// If URL is explicitly provided, use it
	if cmd.URL != "" {
		healthURL := cmd.URL
		if healthURL[len(healthURL)-1] != '/' {
			healthURL += "/"
		}
		healthURL += "health"
		return healthURL, nil
	}

	// Auto-detect from configuration and environment variables
	protocol := "http"
	port := "18888"
	hostname := "localhost"

	// Try to load configuration for auto-detection first
	if _, err := os.Stat(cmd.Config); err == nil {
		cfg, err := config.LoadConfig(cmd.Config)
		if err == nil {
			// Check if autocert is enabled (implies HTTPS)
			if cfg.Autocert != nil && cfg.Autocert.Enabled {
				protocol = "https"
				port = "443"
				// Use the first domain from autocert config
				if len(cfg.Autocert.Domains) > 0 {
					hostname = cfg.Autocert.Domains[0]
				}
			}
		}
	}

	// Check environment variables (overrides config)
	if acmeURL := os.Getenv("OIDCLD_ACME_DIRECTORY_URL"); acmeURL != "" {
		protocol = "https"
		port = "443"
		if domain := os.Getenv("OIDCLD_ACME_DOMAIN"); domain != "" {
			hostname = domain
		}
	}

	// Override port if specified
	if cmd.Port != "" {
		port = cmd.Port
	}

	// Construct URL
	healthURL := fmt.Sprintf("%s://%s:%s/health", protocol, hostname, port)
	return healthURL, nil
}

func main() {
	// Get executable name for help text
	execName := filepath.Base(os.Args[0])

	// Parse command line arguments
	ctx := kong.Parse(&cli,
		kong.Name(execName),
		kong.Description("OpenID Connect Test Identity Provider"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
	)

	// Execute the selected command
	if err := ctx.Run(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
