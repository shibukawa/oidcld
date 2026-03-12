package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/shibukawa/oidcld/internal/server"
)

var (
	ErrAutocertConflictProvidedFiles = fmt.Errorf("autocert is configured and automatic autocert start is available; do not provide TLS cert/key files when using autocert")
	ErrAutocertNoCertsUnavailable    = fmt.Errorf("autocert configured but no cert/key provided and automatic autocert start is unavailable")
)

const defaultHTTPSReadOnlyPort = "18888"

// ServeCmd represents the command to start the OpenID Connect server
type ServeCmd struct {
	Config           string `short:"c" help:"Configuration file path" default:"oidcld.yaml"`
	Port             string `short:"p" help:"Port to listen on (default: 18888 for HTTP, 18443 for HTTPS)" default:""`
	HTTPReadOnlyPort string `name:"http-readonly-port" help:"Restricted HTTP metadata port in HTTPS mode (default: 18888, or off/disabled/0 to disable)" default:""`
	Watch            bool   `short:"w" help:"Watch configuration file for changes and reload automatically"`
	CertFile         string `help:"Path to TLS certificate file (for HTTPS)"`
	KeyFile          string `help:"Path to TLS private key file (for HTTPS)"`
	Verbose          bool   `short:"v" help:"Enable verbose logging (including health check logs)" env:"OIDCLD_VERBOSE"`
	// Autocert is configured via environment variables only. CLI autocert flags removed.
}

// Run executes the serve command to start the OpenID Connect server
func (cmd *ServeCmd) Run() error {
	// Load configuration, allowing config package to consider environment
	// autocert overrides internally.
	cfg, err := config.LoadConfig(cmd.Config, cmd.Verbose)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	effectivePort := resolveServePort(cmd.Port, shouldUseHTTPSByDefault(cfg, cmd.CertFile, cmd.KeyFile))

	// Let config package prepare serve-time defaults (autocert may force HTTPS)
	useHTTPS, msg := cfg.PrepareForServe(&config.ServeOptions{Port: effectivePort, Verbose: cmd.Verbose})
	if msg != "" {
		color.Cyan(msg)
	}

	// Auto-enable HTTPS if explicit cert files provided (both) and not already enabled via autocert
	if !useHTTPS && cmd.CertFile != "" && cmd.KeyFile != "" {
		useHTTPS = true
		color.Cyan("🔧 Auto-enabling HTTPS mode due to provided certificate files")
		// Ensure issuer uses https if previously synthesized
		if cfg.OIDCLD.Issuer == fmt.Sprintf("http://localhost:%s", effectivePort) {
			cfg.OIDCLD.Issuer = fmt.Sprintf("https://localhost:%s", effectivePort)
		}
	}

	// If autocert is enabled, log the renewal threshold days for operator visibility
	if cfg.Autocert != nil && cfg.Autocert.Enabled {
		color.Cyan("🔁 Autocert renewal threshold: %d days", cfg.Autocert.RenewalThreshold)
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
	if useHTTPS {
		httpReadOnlyPort := resolveHTTPReadOnlyPort(cmd.HTTPReadOnlyPort, effectivePort, useHTTPS)
		if httpReadOnlyPort != "" {
			color.Cyan("🔎 HTTP metadata companion listener enabled on port %s (discovery/JWKS/health only)", httpReadOnlyPort)
		} else if strings.TrimSpace(cmd.HTTPReadOnlyPort) != "" {
			color.Cyan("🔎 HTTP metadata companion listener disabled")
		}

		// If autocert is configured but server package doesn't provide an autocert starter,
		// attempt to start with provided cert/key. If none provided, return helpful error.
		if cfg.Autocert != nil && cfg.Autocert.Enabled {
			// If server supports autocert, prefer it — but error if user also provided cert/key.
			if srv.SupportsAutocert() {
				if cmd.CertFile != "" || cmd.KeyFile != "" {
					return ErrAutocertConflictProvidedFiles
				}
				color.Cyan("🔄 Autocert is configured and available - starting HTTPS with autocert...")
				return srv.StartTLSWithHTTPReadOnly(effectivePort, httpReadOnlyPort, "", "")
			}

			// Fallback: try using provided cert/key files if available when autocert is configured
			// but not available in this build.
			color.Cyan("🔄 Autocert is configured, but automatic autocert start is not available in this build. Trying TLS certificates if provided...")
			if cmd.CertFile != "" && cmd.KeyFile != "" {
				return srv.StartTLSWithHTTPReadOnly(effectivePort, httpReadOnlyPort, cmd.CertFile, cmd.KeyFile)
			}
			return ErrAutocertNoCertsUnavailable
		}

		color.Cyan("🔄 Starting server with TLS certificates...")
		return srv.StartTLSWithHTTPReadOnly(effectivePort, httpReadOnlyPort, cmd.CertFile, cmd.KeyFile)
	}
	color.Cyan("🔄 Starting server with HTTP...")
	return srv.Start(effectivePort)
}

func shouldUseHTTPSByDefault(cfg *config.Config, certFile, keyFile string) bool {
	if cfg != nil {
		if strings.HasPrefix(cfg.OIDCLD.Issuer, "https://") {
			return true
		}
		if cfg.Autocert != nil && cfg.Autocert.Enabled {
			return true
		}
	}
	return certFile != "" && keyFile != ""
}

func resolveServePort(cliPort string, useHTTPS bool) string {
	if strings.TrimSpace(cliPort) != "" {
		return strings.TrimSpace(cliPort)
	}
	return config.DefaultServePort(useHTTPS)
}

func normalizeCLIHTTPReadOnlyPort(port string) string {
	switch strings.ToLower(strings.TrimSpace(port)) {
	case "", "auto":
		return ""
	case "0", "off", "disabled", "none":
		return "disabled"
	default:
		return strings.TrimSpace(port)
	}
}

func resolveHTTPReadOnlyPort(cliPort, primaryPort string, useHTTPS bool) string {
	if !useHTTPS {
		return ""
	}
	switch normalized := normalizeCLIHTTPReadOnlyPort(cliPort); normalized {
	case "disabled":
		return ""
	case "":
		if primaryPort == defaultHTTPSReadOnlyPort {
			return ""
		}
		return defaultHTTPSReadOnlyPort
	default:
		return normalized
	}
}

// setupConfigWatcher sets up file system watching for configuration changes
func (cmd *ServeCmd) setupConfigWatcher(srv *server.Server) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Add config file to watcher
	if err := watcher.Add(cmd.Config); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch config file %s: %w", cmd.Config, err)
	}

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

				// Only handle write events
				if event.Op&fsnotify.Write == fsnotify.Write {
					// Cancel previous timer if it exists
					if debounceTimer != nil {
						debounceTimer.Stop()
					}

					// Set new timer for debounced reload
					debounceTimer = time.AfterFunc(debounceDelay, func() {
						cmd.reloadConfig(srv)
					})
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				color.Red("❌ File watcher error: %v", err)
			}
		}
	}()

	return nil
}

// reloadConfig reloads the configuration and updates the server
func (cmd *ServeCmd) reloadConfig(srv *server.Server) {
	color.Cyan("\n🔄 Configuration file changed, reloading...")

	// Load new configuration; config package will apply environment overrides
	// internally when present.
	newCfg, err := config.LoadConfig(cmd.Config, cmd.Verbose)
	if err != nil {
		color.Red("❌ Failed to reload configuration: %v", err)
		color.Red("   Keeping previous configuration")
		return
	}

	// Update server configuration
	if err := srv.UpdateConfig(newCfg); err != nil {
		color.Red("❌ Failed to update server configuration: %v", err)
		color.Red("   Keeping previous configuration")
		return
	}

	// Success message with configuration details
	color.Green("✅ Configuration reloaded successfully!")
	color.Cyan("📋 Updated configuration:")
	color.Cyan("   Issuer: %s", newCfg.OIDCLD.Issuer)
	color.Cyan("   Users: %d", len(newCfg.Users))
	color.Cyan("   Valid Scopes: %v", newCfg.OIDCLD.ValidScopes)
	if newCfg.Autocert != nil && newCfg.Autocert.Enabled {
		color.Cyan("   Autocert: enabled (%v)", newCfg.Autocert.Domains)
	}
	color.Cyan("   Timestamp: %s", time.Now().Format("15:04:05"))
	fmt.Println()
}
