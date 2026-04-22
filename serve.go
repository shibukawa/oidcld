package main

import (
	"fmt"
	"os"
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
	ErrProxyPortConflict             = fmt.Errorf("proxy listener port conflicts with an existing listener")
	ErrManualTLSFilesIncomplete      = fmt.Errorf("both TLS certificate and key files are required for manual TLS")
)

// ServeCmd represents the command to start the OpenID Connect server
type ServeCmd struct {
	Config           string `short:"c" help:"Configuration file path" default:"oidcld.yaml"`
	Port             string `short:"p" help:"Port to listen on (default: 8080 for HTTP, 8443 for HTTPS)" default:""`
	ConsolePort      string `name:"console-port" help:"Developer Console listener port" default:""`
	ProxyPort        string `name:"proxy-port" help:"Optional dedicated reverse proxy listener port. When omitted, OIDC and reverse proxy share the main listener." default:""`
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
	if config.IsContainerRuntime() {
		if cfg.AccessFilterExplicit() {
			color.Yellow("⚠ access_filter is explicitly configured while container runtime was detected; keeping enabled=%v", cfg.AccessFilter.Enabled)
		} else if cfg.AccessFilter != nil && !cfg.AccessFilter.Enabled {
			color.Cyan("ℹ access_filter defaulted to disabled because container runtime was detected")
		}
	}

	effectiveProxyPort := resolveProxyPort(cmd.ProxyPort)
	splitProxy := effectiveProxyPort != ""
	useHTTPSDefault := shouldUseOIDCHTTPSByDefault(cfg, cmd.CertFile, cmd.KeyFile)
	effectivePort := resolveServePort(cmd.Port, useHTTPSDefault)

	// Let config package prepare serve-time defaults (autocert may force HTTPS)
	useHTTPS, _ := cfg.PrepareForServe(&config.ServeOptions{Port: effectivePort, ProxyPort: effectiveProxyPort, Verbose: cmd.Verbose})
	effectivePort = resolveServePort(cmd.Port, useHTTPS)
	adminPort := resolveConsolePort(cmd.ConsolePort)

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
	adminBindAddress := ""
	if adminEnabled {
		adminBindAddress = cfg.Console.BindAddress
		srv.SetConsolePort(adminPort)
	}
	if splitProxy {
		if adminEnabled && adminPort != "" && adminPort == effectiveProxyPort {
			return ErrProxyPortConflict
		}
		if err := cfg.ValidateSplitListenerPorts(effectivePort, effectiveProxyPort, adminPort); err != nil {
			return err
		}
	}

	// If watch mode is enabled, set up file watching
	if cmd.Watch {
		if err := cmd.setupConfigWatcher(srv); err != nil {
			return fmt.Errorf("failed to setup config watcher: %w", err)
		}
	}

	proxyUseHTTPS, err := shouldUseReverseProxyHTTPS(cfg, effectiveProxyPort)
	if err != nil {
		return err
	}

	// Start server with HTTPS options
	if !splitProxy {
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

	manualCertFile := firstNonEmpty(strings.TrimSpace(cmd.CertFile), strings.TrimSpace(cfg.OIDC.TLSCertFile))
	manualKeyFile := firstNonEmpty(strings.TrimSpace(cmd.KeyFile), strings.TrimSpace(cfg.OIDC.TLSKeyFile))
	if (manualCertFile == "") != (manualKeyFile == "") {
		return ErrManualTLSFilesIncomplete
	}
	if adminEnabled && adminPort != "" && adminPort == effectivePort {
		return ErrAdminConsolePortConflict
	}

	var listeners []func() error
	if useHTTPS {
		var oidcRunner func() error
		if cfg.Autocert != nil && cfg.Autocert.Enabled {
			if srv.SupportsAutocert() {
				if manualCertFile != "" || manualKeyFile != "" {
					return ErrAutocertConflictProvidedFiles
				}
				oidcRunner = func() error {
					return srv.StartTLSOIDC(effectivePort, "", "")
				}
			} else {
				if manualCertFile != "" && manualKeyFile != "" {
					if err := server.ValidateIssuerMatchesCertificate(cfg.OIDC.Issuer, manualCertFile); err != nil {
						return err
					}
					oidcRunner = func() error {
						return srv.StartTLSOIDC(effectivePort, manualCertFile, manualKeyFile)
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
			oidcRunner = func() error {
				return srv.StartTLSOIDC(effectivePort, manualCertFile, manualKeyFile)
			}
		}
		listeners = append(listeners, oidcRunner)
	} else {
		listeners = append(listeners, func() error {
			return srv.StartOIDC(effectivePort)
		})
	}

	if proxyUseHTTPS {
		listeners = append(listeners, func() error {
			return srv.StartTLSReverseProxy(effectiveProxyPort, manualCertFile, manualKeyFile)
		})
	} else {
		listeners = append(listeners, func() error {
			return srv.StartReverseProxy(effectiveProxyPort)
		})
	}
	if adminEnabled {
		listeners = append(listeners, func() error {
			return srv.StartAdmin(adminBindAddress, adminPort)
		})
	}

	return runConcurrentListeners(listeners...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func shouldUseOIDCHTTPSByDefault(cfg *config.Config, certFile, keyFile string) bool {
	if cfg != nil {
		if strings.HasPrefix(cfg.OIDC.Issuer, "https://") {
			return true
		}
		if cfg.Autocert != nil && cfg.Autocert.Enabled {
			return true
		}
	}
	return certFile != "" && keyFile != ""
}

func shouldUseReverseProxyHTTPS(cfg *config.Config, proxyPort string) (bool, error) {
	if strings.TrimSpace(proxyPort) == "" {
		return false, nil
	}
	if cfg == nil {
		return false, nil
	}
	scheme, err := cfg.ReverseProxyListenerScheme()
	if err != nil {
		return false, err
	}
	return strings.EqualFold(scheme, "https"), nil
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

func runConcurrentListeners(listeners ...func() error) error {
	if len(listeners) == 0 {
		return nil
	}
	if len(listeners) == 1 {
		return listeners[0]()
	}

	errCh := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func(run func() error) {
			errCh <- run()
		}(listener)
	}
	return <-errCh
}

func resolveServePort(cliPort string, useHTTPS bool) string {
	if strings.TrimSpace(cliPort) != "" {
		return strings.TrimSpace(cliPort)
	}
	if value := strings.TrimSpace(os.Getenv("PORT")); value != "" {
		return value
	}
	return defaultServePort(useHTTPS)
}

func resolveConsolePort(cliPort string) string {
	if strings.TrimSpace(cliPort) != "" {
		return strings.TrimSpace(cliPort)
	}
	if value := strings.TrimSpace(os.Getenv("CONSOLE_PORT")); value != "" {
		return value
	}
	return defaultConsolePort()
}

func resolveProxyPort(cliPort string) string {
	if strings.TrimSpace(cliPort) != "" {
		return strings.TrimSpace(cliPort)
	}
	if value := strings.TrimSpace(os.Getenv("PROXY_PORT")); value != "" {
		return value
	}
	return ""
}

func defaultServePort(useHTTPS bool) string {
	if isContainerRuntime() {
		if useHTTPS {
			return "443"
		}
		return "80"
	}
	return config.DefaultServePort(useHTTPS)
}

func defaultConsolePort() string {
	return "8888"
}

func isContainerRuntime() bool {
	return config.IsContainerRuntime()
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
