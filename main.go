// Package main provides the OIDCLD command-line interface
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/shibukawa/oidcld/internal/mcp"
	"github.com/shibukawa/oidcld/internal/server"
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

// InitCmd represents the command to initialize configuration
type InitCmd struct {
	Config    string `arg:"" help:"Configuration file path" default:"oidcld.yaml"`
	Template  string `help:"Template to use" enum:"standard,entraid-v1,entraid-v2," default:""`
	TenantID  string `help:"Tenant ID for EntraID templates"`
	Port      string `short:"p" help:"Port number for issuer URL"`
	Issuer    string `help:"Custom issuer URL"`
	Cert      string `help:"Generate certificate with algorithm" enum:"RS256,RS384,RS512,ES256,ES384,ES512," default:""`
	HTTPS     bool   `help:"Enable HTTPS mode (default for EntraID templates)"`
	Mkcert    bool   `help:"Generate mkcert certificates for HTTPS"`
	Overwrite bool   `short:"w" help:"Overwrite existing files without confirmation"`
}

// ServeCmd represents the command to start the OpenID Connect server
type ServeCmd struct {
	Config   string `short:"c" help:"Configuration file path" default:"oidcld.yaml"`
	Port     string `short:"p" help:"Port to listen on" default:"18888"`
	Watch    bool   `short:"w" help:"Watch configuration file for changes and reload automatically"`
	HTTPS    bool   `help:"Enable HTTPS server"`
	CertFile string `help:"Path to TLS certificate file (for HTTPS)"`
	KeyFile  string `help:"Path to TLS private key file (for HTTPS)"`
}

// Run executes the initialization command with the provided configuration.
func (cmd *InitCmd) Run() error {
	// Run wizard if template is not specified
	if cmd.Template == "" {
		if err := cmd.runWizard(); err != nil {
			return fmt.Errorf("wizard failed: %w", err)
		}
	}

	// Check for existing files unless overwrite is specified
	if !cmd.Overwrite {
		if err := cmd.checkExistingFiles(); err != nil {
			return err
		}
	}

	// Determine config mode based on template
	var mode config.Mode
	switch cmd.Template {
	case "entraid-v1":
		mode = config.ModeEntraIDv1
		cmd.HTTPS = true // EntraID requires HTTPS
	case "entraid-v2":
		mode = config.ModeEntraIDv2
		cmd.HTTPS = true // EntraID requires HTTPS
	default:
		mode = config.ModeStandard
	}

	// Initialize configuration
	cfg, err := config.CreateDefaultConfig(mode)
	if err != nil {
		return fmt.Errorf("failed to create default configuration: %w", err)
	}

	// Apply custom settings
	if cmd.TenantID != "" && cfg.EntraID != nil {
		cfg.EntraID.TenantID = cmd.TenantID
		// Update issuer for EntraID modes
		if mode == config.ModeEntraIDv2 {
			cfg.OIDCLD.Issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cmd.TenantID)
		}
	}

	switch {
	case cmd.Port != "" && cmd.Issuer != "":
		cfg.OIDCLD.Issuer = cmd.Issuer
	case cmd.Port != "" && mode == config.ModeStandard:
		if cmd.HTTPS {
			cfg.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", cmd.Port)
		} else {
			cfg.OIDCLD.Issuer = fmt.Sprintf("http://localhost:%s", cmd.Port)
		}
	case cmd.Issuer != "":
		cfg.OIDCLD.Issuer = cmd.Issuer
	case mode == config.ModeStandard:
		// Set default issuer based on HTTPS setting
		defaultPort := "18888"
		if cmd.HTTPS {
			cfg.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", defaultPort)
		} else {
			cfg.OIDCLD.Issuer = fmt.Sprintf("http://localhost:%s", defaultPort)
		}
	}

	// Handle certificate generation
	if cmd.Cert != "" {
		if err := config.GenerateCertificates(cmd.Cert, cfg); err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}
	}

	// Handle mkcert certificate generation for HTTPS
	// Generate if explicitly requested, or if HTTPS is enabled and not explicitly disabled
	if cmd.Mkcert {
		if err := cmd.generateMkcertCertificates(); err != nil {
			return fmt.Errorf("failed to generate mkcert certificates: %w", err)
		}
	}

	// Save configuration
	if err := config.SaveConfig(cmd.Config, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	color.Green("Configuration initialized successfully!")
	color.Cyan("  File: %s", cmd.Config)
	color.Cyan("  Template: %s", cmd.Template)

	if cmd.TenantID != "" {
		color.Cyan("  Tenant ID: %s", cmd.TenantID)
	}

	if cmd.Cert != "" {
		fmt.Printf("  Certificate Algorithm: %s\n", cmd.Cert)
		fmt.Printf("  Private Key: %s\n", cfg.OIDCLD.PrivateKeyPath)
		fmt.Printf("  Public Key: %s\n", cfg.OIDCLD.PublicKeyPath)
	}

	if cmd.HTTPS {
		fmt.Printf("  HTTPS: enabled\n")
		if cmd.Mkcert {
			fmt.Printf("  TLS Certificate: localhost.pem\n")
			fmt.Printf("  TLS Private Key: localhost-key.pem\n")
		}
	}

	fmt.Printf("  Issuer: %s\n", cfg.OIDCLD.Issuer)
	algorithm := cfg.OIDCLD.Algorithm
	if algorithm == "" {
		algorithm = "RS256" // Default
	}
	fmt.Printf("  Algorithm: %s\n", algorithm)
	fmt.Printf("  Users: %d\n", len(cfg.Users))

	if cfg.EntraID != nil {
		fmt.Printf("  EntraID Mode: %s\n", cfg.EntraID.Version)
	}

	return nil
}

// runWizard runs an interactive wizard to configure the initialization
func (cmd *InitCmd) runWizard() error {
	reader := bufio.NewReader(os.Stdin)

	color.Cyan("OIDCLD Configuration Wizard")
	color.Cyan("=============================")
	color.Cyan("")

	// Template selection
	fmt.Println("Select template:")
	fmt.Println("1. Standard OpenID Connect (default)")
	fmt.Println("2. EntraID/AzureAD v1.0")
	fmt.Println("3. EntraID/AzureAD v2.0")
	color.Yellow("Enter choice [1-3] (default: 1): ")

	templateChoice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read template choice: %w", err)
	}
	templateChoice = strings.TrimSpace(templateChoice)

	switch templateChoice {
	case "", "1":
		cmd.Template = "standard"
	case "2":
		cmd.Template = "entraid-v1"
	case "3":
		cmd.Template = "entraid-v2"
	default:
		return fmt.Errorf("%w: %s", ErrInvalidTemplateChoice, templateChoice)
	}

	// EntraID-specific configuration
	if cmd.Template == "entraid-v1" || cmd.Template == "entraid-v2" {
		color.Yellow("Enter Tenant ID (optional): ")
		tenantID, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read tenant ID: %w", err)
		}
		cmd.TenantID = strings.TrimSpace(tenantID)
		cmd.HTTPS = true // EntraID requires HTTPS

		// Ask about mkcert even for EntraID templates
		fmt.Println()
		fmt.Println("HTTPS Certificate Configuration:")
		color.Yellow("Generate mkcert certificates for HTTPS? [Y/n]: ")
		mkcertChoice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read mkcert choice: %w", err)
		}
		mkcertChoice = strings.TrimSpace(strings.ToLower(mkcertChoice))
		cmd.Mkcert = mkcertChoice != "n" && mkcertChoice != "no"
	}

	// HTTPS configuration for standard template
	if cmd.Template == "standard" {
		fmt.Println()
		fmt.Println("HTTPS Configuration:")
		fmt.Print("Enable HTTPS? [y/N]: ")
		httpsChoice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read HTTPS choice: %w", err)
		}
		httpsChoice = strings.TrimSpace(strings.ToLower(httpsChoice))
		cmd.HTTPS = httpsChoice == "y" || httpsChoice == "yes"

		if cmd.HTTPS {
			fmt.Print("Generate mkcert certificates? [Y/n]: ")
			mkcertChoice, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read mkcert choice: %w", err)
			}
			mkcertChoice = strings.TrimSpace(strings.ToLower(mkcertChoice))
			cmd.Mkcert = mkcertChoice != "n" && mkcertChoice != "no"
		}
	}

	// Port configuration for standard template
	if cmd.Template == "standard" {
		fmt.Print("Enter port number (default: 18888): ")
		port, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read port: %w", err)
		}
		port = strings.TrimSpace(port)
		if port != "" {
			// Validate port number
			if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
				return fmt.Errorf("%w: %s", ErrInvalidPortNumber, port)
			}
			cmd.Port = port
		}
	}

	// Custom issuer
	fmt.Print("Enter custom issuer URL (optional): ")
	issuer, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read issuer: %w", err)
	}
	cmd.Issuer = strings.TrimSpace(issuer)

	// Certificate generation
	fmt.Println()
	fmt.Println("Certificate generation:")
	fmt.Println("1. No certificate generation (default)")
	fmt.Println("2. RS256 (RSA 2048-bit)")
	fmt.Println("3. RS384 (RSA 3072-bit)")
	fmt.Println("4. RS512 (RSA 4096-bit)")
	fmt.Println("5. ES256 (ECDSA P-256)")
	fmt.Println("6. ES384 (ECDSA P-384)")
	fmt.Println("7. ES512 (ECDSA P-521)")
	fmt.Print("Enter choice [1-7] (default: 1): ")

	certChoice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read certificate choice: %w", err)
	}
	certChoice = strings.TrimSpace(certChoice)

	switch certChoice {
	case "", "1":
		cmd.Cert = ""
	case "2":
		cmd.Cert = "RS256"
	case "3":
		cmd.Cert = "RS384"
	case "4":
		cmd.Cert = "RS512"
	case "5":
		cmd.Cert = "ES256"
	case "6":
		cmd.Cert = "ES384"
	case "7":
		cmd.Cert = "ES512"
	default:
		return fmt.Errorf("%w: %s", ErrInvalidCertificateChoice, certChoice)
	}

	// Overwrite confirmation
	if !cmd.Overwrite {
		filesToCheck := []string{cmd.Config}
		if cmd.Cert != "" {
			filesToCheck = append(filesToCheck, ".oidcld.key", ".oidcld.pub.key")
		}

		var existingFiles []string
		for _, file := range filesToCheck {
			if _, err := os.Stat(file); err == nil {
				existingFiles = append(existingFiles, file)
			}
		}

		if len(existingFiles) > 0 {
			fmt.Println()
			fmt.Printf("Warning: The following files already exist:\n")
			for _, file := range existingFiles {
				fmt.Printf("  - %s\n", file)
			}
			fmt.Print("Overwrite existing files? [y/N]: ")

			overwriteChoice, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read overwrite choice: %w", err)
			}
			overwriteChoice = strings.TrimSpace(strings.ToLower(overwriteChoice))

			if overwriteChoice == "y" || overwriteChoice == "yes" {
				cmd.Overwrite = true
			} else {
				return ErrOperationCancelled
			}
		}
	}

	fmt.Println()
	fmt.Println("Configuration summary:")
	fmt.Printf("  Template: %s\n", cmd.Template)
	if cmd.TenantID != "" {
		fmt.Printf("  Tenant ID: %s\n", cmd.TenantID)
	}
	if cmd.Port != "" {
		fmt.Printf("  Port: %s\n", cmd.Port)
	}
	if cmd.Issuer != "" {
		fmt.Printf("  Issuer: %s\n", cmd.Issuer)
	}
	if cmd.Cert != "" {
		fmt.Printf("  Certificate: %s\n", cmd.Cert)
	}
	if cmd.HTTPS {
		fmt.Printf("  HTTPS: enabled\n")
		if cmd.Mkcert {
			fmt.Printf("  mkcert: enabled\n")
		}
	}
	fmt.Printf("  Config file: %s\n", cmd.Config)
	fmt.Println()

	return nil
}

// Run starts the OpenID Connect server
func (cmd *ServeCmd) Run() error {
	// Load initial configuration
	cfg, err := config.LoadConfig(cmd.Config)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Update issuer URL based on HTTPS setting if not explicitly set
	if cmd.HTTPS && cfg.OIDCLD.Issuer == "" {
		cfg.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", cmd.Port)
	} else if !cmd.HTTPS && cfg.OIDCLD.Issuer == "" {
		cfg.OIDCLD.Issuer = fmt.Sprintf("http://localhost:%s", cmd.Port)
	}

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// If watch mode is enabled, set up file watching
	if cmd.Watch {
		color.Cyan("🔄 Watch mode enabled - configuration will be reloaded automatically on changes")
		if err := cmd.setupConfigWatcher(srv); err != nil {
			return fmt.Errorf("failed to setup config watcher: %w", err)
		}
	}

	// Start server with HTTPS options
	if cmd.HTTPS {
		return srv.StartTLS(cmd.Port, cmd.CertFile, cmd.KeyFile)
	}
	return srv.Start(cmd.Port)
}

// setupConfigWatcher sets up file system watching for configuration changes
func (cmd *ServeCmd) setupConfigWatcher(srv *server.Server) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Get absolute path of config file
	configPath, err := filepath.Abs(cmd.Config)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of config file: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrConfigFileNotExist, configPath)
	}

	// Watch the config file
	err = watcher.Add(configPath)
	if err != nil {
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	color.Blue("👀 Watching configuration file: %s", configPath)

	// Start watching in a goroutine
	go func() {
		defer watcher.Close()

		// Debounce timer to avoid multiple rapid reloads
		var debounceTimer *time.Timer
		const debounceDelay = 500 * time.Millisecond

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only react to write events (file modifications)
				if event.Has(fsnotify.Write) {
					color.Yellow("📝 Configuration file changed: %s", event.Name)

					// Cancel previous timer if it exists
					if debounceTimer != nil {
						debounceTimer.Stop()
					}

					// Set up debounce timer to avoid rapid successive reloads
					debounceTimer = time.AfterFunc(debounceDelay, func() {
						cmd.reloadConfiguration(srv, configPath)
					})
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				color.Red("⚠️  File watcher error: %v", err)
			}
		}
	}()

	return nil
}

// reloadConfiguration reloads the configuration and updates the server
func (cmd *ServeCmd) reloadConfiguration(srv *server.Server, configPath string) {
	// Load new configuration
	newCfg, err := config.LoadConfig(configPath)
	if err != nil {
		srv.GetPrettyLogger().ConfigReloadFailed(configPath, err)
		return
	}

	// Update server configuration
	if err := srv.UpdateConfig(newCfg); err != nil {
		srv.GetPrettyLogger().ConfigReloadFailed(configPath, err)
		return
	}
}

// MCPCmd represents the MCP server command
type MCPCmd struct {
	Config string `short:"c" help:"Configuration file path" default:"oidcld.yaml"`
	Port   string `short:"p" help:"Port to listen on for HTTP mode (if not specified, uses stdin/stdout)"`
}

// Run starts the MCP server
func (cmd *MCPCmd) Run() error {
	// Import the MCP package
	mcpServer := mcp.NewMCPServer(cmd.Config)

	ctx := context.Background()

	if cmd.Port != "" {
		// HTTP mode
		color.Green("🚀 Starting MCP server in HTTP mode on port %s", cmd.Port)
		color.Cyan("   Connect to: http://localhost:%s", cmd.Port)
		return mcpServer.ServeHTTP(ctx, cmd.Port)
	}
	// stdin/stdout mode
	color.Green("🚀 Starting MCP server in stdin/stdout mode")
	color.Cyan("   Ready for JSON-RPC communication")
	return mcpServer.ServeStdio(ctx)
}

// HealthCmd represents the health check command
type HealthCmd struct {
	URL     string `short:"u" help:"Server URL to check" default:"http://localhost:18888"`
	Timeout string `short:"t" help:"Timeout duration" default:"5s"`
}

// Run performs a health check
func (cmd *HealthCmd) Run() error {
	timeout, err := time.ParseDuration(cmd.Timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout duration: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check health endpoint
	healthURL := strings.TrimSuffix(cmd.URL, "/") + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("❌ Failed to create health check request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("❌ Health check failed: %w", err)
	}
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()

	if resp.StatusCode == http.StatusOK {
		color.Green("✅ Server is healthy")
		return nil
	}
	color.Red("❌ Server returned status: %d", resp.StatusCode)
	return fmt.Errorf("%w: status %d", ErrHealthCheckFailed, resp.StatusCode)
}

// checkExistingFiles checks if configuration or key files already exist
func (cmd *InitCmd) checkExistingFiles() error {
	filesToCheck := []string{cmd.Config}

	// Add key files if certificate generation is requested
	if cmd.Cert != "" {
		filesToCheck = append(filesToCheck, ".oidcld.key", ".oidcld.pub.key")
	}

	// Add mkcert certificate files if HTTPS is enabled
	if cmd.Mkcert || cmd.HTTPS {
		filesToCheck = append(filesToCheck, "localhost.pem", "localhost-key.pem")
	}

	var existingFiles []string
	for _, file := range filesToCheck {
		if _, err := os.Stat(file); err == nil {
			existingFiles = append(existingFiles, file)
		}
	}

	if len(existingFiles) > 0 {
		return fmt.Errorf("%w:\n  %s\nPlease remove them or use different file names",
			ErrFilesExist, strings.Join(existingFiles, "\n  "))
	}

	return nil
}

// generateMkcertCertificates generates TLS certificates using mkcert
func (cmd *InitCmd) generateMkcertCertificates() error {
	// Check if mkcert is available
	if _, err := exec.LookPath("mkcert"); err != nil {
		return fmt.Errorf("%w. Please install mkcert first:\n"+
			"  macOS: brew install mkcert\n"+
			"  Linux: https://github.com/FiloSottile/mkcert#installation\n"+
			"  Windows: https://github.com/FiloSottile/mkcert#installation", ErrMkcertNotInstalled)
	}

	// Generate certificate for localhost
	mkcertCmd := exec.Command("mkcert", "localhost", "127.0.0.1", "::1")
	mkcertCmd.Stdout = os.Stdout
	mkcertCmd.Stderr = os.Stderr

	if err := mkcertCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate mkcert certificates: %w", err)
	}

	// Find the generated files and rename them to standard names
	files, err := filepath.Glob("localhost*.pem")
	if err != nil {
		return fmt.Errorf("failed to find generated certificate files: %w", err)
	}

	var certFile, keyFile string
	for _, file := range files {
		if strings.Contains(file, "key") {
			keyFile = file
		} else {
			certFile = file
		}
	}

	if certFile != "" && certFile != "localhost.pem" {
		if err := os.Rename(certFile, "localhost.pem"); err != nil {
			return fmt.Errorf("failed to rename certificate file: %w", err)
		}
	}

	if keyFile != "" && keyFile != "localhost-key.pem" {
		if err := os.Rename(keyFile, "localhost-key.pem"); err != nil {
			return fmt.Errorf("failed to rename key file: %w", err)
		}
	}

	color.Green("✅ Generated mkcert certificates:")
	color.Cyan("   Certificate: localhost.pem")
	color.Cyan("   Private Key: localhost-key.pem")

	return nil
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("openidld"),
		kong.Description("OpenID Connect Test Identity Provider"),
		kong.UsageOnError(),
	)

	if err := ctx.Run(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
