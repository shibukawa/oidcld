// Package main provides the OIDCLD command-line interface
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
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
	// Do not capture environment until needed for failure diagnostics to
	// avoid noisy successful health check logs in containers.

	// Auto-detect URL if not provided; buildHealthURL now returns whether HTTPS
	// is used, whether we should dial localhost, and an optional SNI hostname
	// to use for TLS ServerName (so we can dial 127.0.0.1 while preserving
	// the certificate's expected name).
	healthURL, isHTTPS, dialLocalhost, sniHost, err := cmd.buildHealthURL()
	if err != nil {
		log.Printf("[health] failed to build health URL: %v", err)
		return fmt.Errorf("failed to build health URL: %w", err)
	}

	// Create HTTP client with timeout. If using HTTPS, allow insecure skip verify
	// because health check may run against self-signed/local certs.
	tlsConfig := &tls.Config{}
	if isHTTPS {
		tlsConfig.InsecureSkipVerify = true
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// If buildHealthURL requested dialing localhost (connect to 127.0.0.1)
	// we override DialContext so the TCP connection goes to the local IP but
	// we do not alter the TLS ServerName (so SNI remains the hostname used
	// in the health URL).
	if dialLocalhost {
		// If we have an explicit SNI hostname, configure it on the TLS
		// client so the ServerName used during the TLS handshake matches
		// the certificate the server presents.
		if sniHost != "" {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: tlsConfig.InsecureSkipVerify, ServerName: sniHost}
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Parse the requested address to extract port
			_, p, err := net.SplitHostPort(addr)
			if err != nil {
				// If parsing failed, fall back to dialing original addr
				d := &net.Dialer{}
				return d.DialContext(ctx, network, addr)
			}
			target := net.JoinHostPort("127.0.0.1", p)
			d := &net.Dialer{}
			return d.DialContext(ctx, network, target)
		}
	}

	client := &http.Client{
		Timeout:   cmd.Timeout,
		Transport: transport,
	}

	// Keep success path quiet: do not emit info-level probe logs here.

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
		// Emit diagnostics only on failure: env, args, config, URL parts, SNI
		log.Printf("[health][error] %v", err)
		log.Printf("[health][cmd] args=%v config=%q url_flag=%q port_flag=%q", os.Args, cmd.Config, cmd.URL, cmd.Port)

		// Selectively print relevant environment variables (capture lazily)
		env := os.Environ()
		for _, e := range env {
			if strings.HasPrefix(e, "OIDCLD_") || strings.HasPrefix(e, "SSL_CERT_FILE") || strings.HasPrefix(e, "HOSTNAME") || strings.HasPrefix(e, "PATH=") {
				log.Printf("[health][env] %s", e)
			}
		}

		// Parse healthURL to show host/port
		if parsed, perr := neturl.Parse(healthURL); perr == nil {
			hostPort := parsed.Host
			h, p, serr := net.SplitHostPort(hostPort)
			if serr == nil {
				log.Printf("[health][target] host=%s port=%s scheme=%s", h, p, parsed.Scheme)
			} else {
				// No explicit port
				log.Printf("[health][target] host=%s scheme=%s", hostPort, parsed.Scheme)
			}
		} else {
			log.Printf("[health][target] failed to parse URL %q: %v", healthURL, perr)
		}

		log.Printf("[health][transport] is_https=%t dial_localhost=%t sni=%q", isHTTPS, dialLocalhost, sniHost)

		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			color.Yellow("⚠️  Warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusOK {
		// Keep success output minimal
		color.Green("✅ Server is healthy")
		return nil
	}

	// Non-200: emit diagnostics similar to connection errors
	color.Red("❌ Server returned status: %d", resp.StatusCode)
	log.Printf("[health][cmd] args=%v config=%q url_flag=%q port_flag=%q", os.Args, cmd.Config, cmd.URL, cmd.Port)
	env := os.Environ()
	for _, e := range env {
		if strings.HasPrefix(e, "OIDCLD_") || strings.HasPrefix(e, "SSL_CERT_FILE") || strings.HasPrefix(e, "HOSTNAME") || strings.HasPrefix(e, "PATH=") {
			log.Printf("[health][env] %s", e)
		}
	}
	if parsed, perr := neturl.Parse(healthURL); perr == nil {
		hostPort := parsed.Host
		h, p, serr := net.SplitHostPort(hostPort)
		if serr == nil {
			log.Printf("[health][target] host=%s port=%s scheme=%s status=%d", h, p, parsed.Scheme, resp.StatusCode)
		} else {
			log.Printf("[health][target] host=%s scheme=%s status=%d", hostPort, parsed.Scheme, resp.StatusCode)
		}
	} else {
		log.Printf("[health][target] failed to parse URL %q: %v", healthURL, perr)
	}
	log.Printf("[health][transport] is_https=%t dial_localhost=%t sni=%q status=%d", isHTTPS, dialLocalhost, sniHost, resp.StatusCode)

	return fmt.Errorf("%w: status %d", ErrHealthCheckFailed, resp.StatusCode)
}

// buildHealthURL constructs the health check URL with auto-detection
func (cmd *HealthCmd) buildHealthURL() (string, bool, bool, string, error) {
	// If URL is explicitly provided, use it
	if cmd.URL != "" {
		healthURL := cmd.URL
		if healthURL[len(healthURL)-1] != '/' {
			healthURL += "/"
		}
		healthURL += "health"

		// Determine if HTTPS
		parsed, err := neturl.Parse(healthURL)
		if err != nil {
			return "", false, false, "", fmt.Errorf("invalid URL provided: %w", err)
		}
		isHTTPS := parsed.Scheme == "https"
		return healthURL, isHTTPS, false, "", nil
	}

	// Auto-detect from configuration and environment variables
	protocol := "http"
	port := "18888"
	hostname := "localhost"

	// Load configuration; prefer explicit CLI flag but fall back to OIDCLD_CONFIG
	// environment variable if present. Attempt cmd.Config first, and if that
	// fails and the env var points to a different file, retry with it.
	cfg, err := config.LoadConfig(cmd.Config, false)
	if err != nil {
		log.Printf("[health] failed to load configuration from %q: %v", cmd.Config, err)
		cfg = nil
		// If environment variable points to another config file, try it.
		if envPath := os.Getenv("OIDCLD_CONFIG"); envPath != "" && envPath != cmd.Config {
			log.Printf("[health] attempting to load configuration from OIDCLD_CONFIG=%s", envPath)
			if cfg2, err2 := config.LoadConfig(envPath, false); err2 == nil {
				cfg = cfg2
				log.Printf("[health] loaded configuration from %s", envPath)
			} else {
				log.Printf("[health] failed to load configuration from %s: %v", envPath, err2)
			}
		}
	}

	// Use loaded config. Prefer explicit issuer if set.
	if cfg != nil {
		if cfg.OIDCLD.Issuer != "" {
			// Parse issuer URL to extract scheme, host and port
			parsed, err := neturl.Parse(cfg.OIDCLD.Issuer)
			if err == nil {
				if parsed.Scheme != "" {
					protocol = parsed.Scheme
				}
				// Extract host and optional port
				host := parsed.Host
				if host != "" {
					h, p, err := net.SplitHostPort(host)
					if err == nil {
						hostname = h
						port = p
					} else {
						// No explicit port
						hostname = host
						switch protocol {
						case "https":
							port = "443"
						case "http":
							port = "80"
						}
					}
				}
			}
		} else if cfg.Autocert != nil && cfg.Autocert.Enabled {
			protocol = "https"
			port = "443"
			if len(cfg.Autocert.Domains) > 0 {
				hostname = cfg.Autocert.Domains[0]
			}
		} else if cfg.OIDCLD.TLSCertFile != "" && cfg.OIDCLD.TLSKeyFile != "" {
			// TLS configured via cert files
			protocol = "https"
			port = "443"
		}
	}

	dialLocalhost := false
	sniHost := ""

	// If we detect we're running in a container with an explicit config file
	// provided via OIDCLD_CONFIG, prefer localhost as the host for health
	// checks so the probe targets the local service inside the container
	// rather than an external DNS name. When we do this, set dialLocalhost
	// so the HTTP transport can connect to 127.0.0.1 while preserving TLS
	// ServerName (SNI) as the original hostname.
	if os.Getenv("OIDCLD_CONFIG") != "" {
		if hostname != "localhost" {
			log.Printf("[health] overriding hostname %q -> localhost because OIDCLD_CONFIG is set", hostname)
			// Preserve the original hostname for SNI
			sniHost = hostname
			hostname = "localhost"
			dialLocalhost = true
		}

		// If the CLI user didn't explicitly override port, prefer the
		// container-internal HTTPS port 443 so probes hit the service
		// inside the container (the host may map it to 8443 externally).
		if cmd.Port == "" && protocol == "https" {
			if port != "443" {
				log.Printf("[health] overriding port %q -> 443 because OIDCLD_CONFIG is set and no explicit port provided", port)
				port = "443"
			}
		}
	}

	// Override port if specified by CLI
	if cmd.Port != "" {
		port = cmd.Port
	}

	// Construct URL
	healthURL := fmt.Sprintf("%s://%s:%s/health", protocol, hostname, port)
	isHTTPS := protocol == "https"
	return healthURL, isHTTPS, dialLocalhost, sniHost, nil
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
