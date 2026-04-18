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
	ErrAdminConsolePortConflict      = fmt.Errorf("admin console port conflicts with an existing listener")
	ErrManualTLSFilesIncomplete      = fmt.Errorf("both TLS certificate and key files are required for manual TLS")
)

// ServeCmd represents the command to start the OpenID Connect server
type ServeCmd struct {
	Config           string `short:"c" help:"Configuration file path" default:"oidcld.yaml"`
	Port             string `short:"p" help:"Port to listen on (default: 18888 for HTTP, 18443 for HTTPS)" default:""`
	HTTPReadOnlyPort string `name:"http-readonly-port" help:"Deprecated. HTTP metadata companion now shares the Developer Console listener." default:""`
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
	useHTTPS, _ := cfg.PrepareForServe(&config.ServeOptions{Port: effectivePort, Verbose: cmd.Verbose})

	// Auto-enable HTTPS if explicit cert files provided (both) and not already enabled via autocert
	if !useHTTPS && cmd.CertFile != "" && cmd.KeyFile != "" {
		useHTTPS = true
		// Ensure issuer uses https if previously synthesized
		if cfg.OIDC.Issuer == fmt.Sprintf("http://localhost:%s", effectivePort) {
			cfg.OIDC.Issuer = fmt.Sprintf("https://localhost:%s", effectivePort)
		}
	}

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	adminEnabled := cfg.Console != nil
	adminPort := ""
	adminBindAddress := ""
	if adminEnabled {
		adminPort = cfg.Console.Port
		adminBindAddress = cfg.Console.BindAddress
	}

	// If watch mode is enabled, set up file watching
	if cmd.Watch {
		if err := cmd.setupConfigWatcher(srv); err != nil {
			return fmt.Errorf("failed to setup config watcher: %w", err)
		}
	}

	// Start server with HTTPS options
	if useHTTPS {
		manualCertFile := firstNonEmpty(strings.TrimSpace(cmd.CertFile), strings.TrimSpace(cfg.OIDC.TLSCertFile))
		manualKeyFile := firstNonEmpty(strings.TrimSpace(cmd.KeyFile), strings.TrimSpace(cfg.OIDC.TLSKeyFile))
		if (manualCertFile == "") != (manualKeyFile == "") {
			return ErrManualTLSFilesIncomplete
		}

		if adminEnabled && adminPort != "" && adminPort == effectivePort {
			return ErrAdminConsolePortConflict
		}

		// If autocert is configured but server package doesn't provide an autocert starter,
		// attempt to start with provided cert/key. If none provided, return helpful error.
		var mainRunner func() error
		if cfg.Autocert != nil && cfg.Autocert.Enabled {
			// If server supports autocert, prefer it — but error if user also provided cert/key.
			if srv.SupportsAutocert() {
				if manualCertFile != "" || manualKeyFile != "" {
					return ErrAutocertConflictProvidedFiles
				}
				mainRunner = func() error {
					return srv.StartTLS(effectivePort, "", "")
				}
			} else {
				// Fallback: try using provided cert/key files if available when autocert is configured
				// but not available in this build.
				if manualCertFile != "" && manualKeyFile != "" {
					if err := server.ValidateIssuerMatchesCertificate(cfg.OIDC.Issuer, manualCertFile); err != nil {
						return err
					}
					mainRunner = func() error {
						return srv.StartTLS(effectivePort, manualCertFile, manualKeyFile)
					}
				} else {
					return ErrAutocertNoCertsUnavailable
				}
			}
		} else {
			if manualCertFile != "" {
				if err := server.ValidateIssuerMatchesCertificate(cfg.OIDC.Issuer, manualCertFile); err != nil {
					return err
				}
			}
			mainRunner = func() error {
				return srv.StartTLS(effectivePort, manualCertFile, manualKeyFile)
			}
		}

		return runServeListeners(mainRunner, adminEnabled, func() error {
			return srv.StartAdmin(adminBindAddress, adminPort)
		})
	}
	if adminEnabled && adminPort != "" && adminPort == effectivePort {
		return ErrAdminConsolePortConflict
	}
	return runServeListeners(func() error {
		return srv.Start(effectivePort)
	}, adminEnabled, func() error {
		return srv.StartAdmin(adminBindAddress, adminPort)
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func shouldUseHTTPSByDefault(cfg *config.Config, certFile, keyFile string) bool {
	if cfg != nil {
		if strings.HasPrefix(cfg.OIDC.Issuer, "https://") {
			return true
		}
		if cfg.Autocert != nil && cfg.Autocert.Enabled {
			return true
		}
		if cfg.ReverseProxyUsesHTTPS() {
			return true
		}
	}
	return certFile != "" && keyFile != ""
}

func runServeListeners(mainRunner func() error, adminEnabled bool, adminRunner func() error) error {
	if !adminEnabled {
		return mainRunner()
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- adminRunner()
	}()
	go func() {
		errCh <- mainRunner()
	}()

	return <-errCh
}

func resolveServePort(cliPort string, useHTTPS bool) string {
	if strings.TrimSpace(cliPort) != "" {
		return strings.TrimSpace(cliPort)
	}
	return config.DefaultServePort(useHTTPS)
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
	color.Cyan("   Issuer: %s", newCfg.OIDC.Issuer)
	color.Cyan("   Users: %d", len(newCfg.Users))
	color.Cyan("   Valid Scopes: %v", newCfg.OIDC.ValidScopes)
	if newCfg.Autocert != nil && newCfg.Autocert.Enabled {
		color.Cyan("   Autocert: enabled (%v)", newCfg.Autocert.Domains)
	}
	color.Cyan("   Timestamp: %s", time.Now().Format("15:04:05"))
	fmt.Println()
}
