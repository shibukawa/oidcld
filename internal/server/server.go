package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	// "log" was removed (diagnostic logs cleaned up)

	// ...existing code...
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"

	// ...existing code...
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

var (
	ErrConfigurationCannotBeNil           = fmt.Errorf("configuration cannot be nil")
	ErrIssuerURLCannotBeChanged           = fmt.Errorf("issuer URL cannot be changed at runtime")
	ErrAutocertConflictTLSProvided        = fmt.Errorf("autocert is configured AND TLS certificate/key were provided; choose one (remove autocert settings or provide no cert/key)")
	ErrTLSMissingWithoutAutocert          = fmt.Errorf("no autocert configured and TLS certificate/key not provided")
	ErrManualTLSCertificateKeyRequired    = errors.New("both TLS certificate and key files are required for manual TLS")
	ErrEntraIDTenantRequiresConfiguration = errors.New("tenant is not allowed without EntraID configuration")
	ErrEntraIDTenantIDMismatch            = errors.New("tenant does not match configured tenant_id")
	ErrEntraIDTenantNotAllowed            = errors.New("tenant is not allowed")
	jwtAudienceClaimFormatMu              sync.Mutex
)

func configureJWTAudienceClaimFormat(format string) {
	jwt.MarshalSingleStringAsArray = format == config.AudienceClaimFormatArray
}

// Server represents the new zitadel/oidc-based server implementation
type Server struct {
	config        *config.Config
	storage       *StorageAdapter
	provider      op.OpenIDProvider
	privateKey    *rsa.PrivateKey
	logger        *slog.Logger
	prettyLog     *Logger // Add colorful logger
	access        *compiledAccessFilter
	managedLeaves map[string]*managedLeafCertificate
	managedLeafMu sync.Mutex

	// Autocert manager (optional)
	autocertManager *AutocertManager
	autocertCancel  context.CancelFunc
	reverseProxy    *compiledReverseProxy
	reverseProxyLog *reverseProxyLogStore
}

// SupportsAutocert reports whether this Server was built with autocert support
// and currently has an initialized autocert manager.
func (s *Server) SupportsAutocert() bool {
	return s != nil && s.autocertManager != nil
}

// generatePrivateKey generates a new RSA private key for JWT signing
func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
func New(cfg *config.Config) (*Server, error) {
	// Generate a private key if not provided
	privateKey, err := generatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create logger
	logger := slog.Default()

	// Create OIDC server
	return NewServer(cfg, privateKey, logger)
}

// NewServer creates a new server using zitadel/oidc/v3
func NewServer(cfg *config.Config, privateKey *rsa.PrivateKey, logger *slog.Logger) (*Server, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, fmt.Errorf("failed to normalize configuration: %w", err)
	}

	jwtAudienceClaimFormatMu.Lock()
	configureJWTAudienceClaimFormat(cfg.OIDC.NormalizedAudienceClaimFormat())
	jwtAudienceClaimFormatMu.Unlock()

	// Create storage adapter
	storage := NewStorageAdapter(cfg, privateKey)

	// Create the server instance
	server := &Server{
		config:        cfg,
		storage:       storage,
		privateKey:    privateKey,
		logger:        logger,
		prettyLog:     NewLogger(), // Initialize colorful logger
		managedLeaves: map[string]*managedLeafCertificate{},
	}

	var err error
	server.access, err = newCompiledAccessFilter(cfg.AccessFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to build access filter: %w", err)
	}
	server.reverseProxy, err = newCompiledReverseProxy(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build reverse proxy routes: %w", err)
	}
	server.reverseProxyLog = newReverseProxyLogStore(reverseProxyLogRetention(cfg))

	// Initialize the OpenID Provider
	provider, err := server.createProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenID provider: %w", err)
	}

	server.provider = provider

	// Initialize AutocertManager if autocert is enabled in configuration.
	if cfg.Autocert != nil && cfg.Autocert.Enabled {
		am, err := NewAutocertManager(cfg.Autocert, server.prettyLog)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize autocert manager: %w", err)
		}
		_, cancel := context.WithCancel(context.Background())
		server.autocertManager = am
		server.autocertCancel = cancel

		// The renewal monitor is now handled via RenewBefore, so we do not start it here.
	}

	return server, nil
}

// createProvider creates the zitadel OpenID Provider with proper configuration
func (s *Server) createProvider() (op.OpenIDProvider, error) {
	// Create encryption key for tokens (32 bytes required)
	key := sha256.Sum256([]byte("oidcld-encryption-key-" + s.config.OIDC.Issuer))

	// Configure the OpenID Provider
	config := &op.Config{
		CryptoKey: key,

		// Default logout redirect URI
		DefaultLogoutRedirectURI: "/logged-out",

		// Enable PKCE with S256
		CodeMethodS256: s.config.OIDC.PKCERequired,

		// Enable form post authentication (in addition to HTTP Basic Auth)
		AuthMethodPost: true,

		// Enable private key JWT authentication
		AuthMethodPrivateKeyJWT: true,

		// Enable refresh token grant
		GrantTypeRefreshToken: s.config.OIDC.RefreshTokenEnabled,

		// Enable request object parameter
		RequestObjectSupported: true,

		// Set supported UI locales
		SupportedUILocales: []language.Tag{language.English},

		// Device authorization configuration
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}

	// Determine issuer URL
	issuer := s.config.OIDC.Issuer
	if issuer == "" {
		issuer = "http://localhost:18888" // Default for development
	}

	// Create the provider with options
	provider, err := op.NewProvider(config, s.storage, op.StaticIssuer(issuer),
		// Allow insecure HTTP for development
		op.WithAllowInsecure(),
		// Custom authorization endpoint (optional)
		op.WithCustomAuthEndpoint(op.NewEndpoint("authorize")),
		// Custom token endpoint - use /token instead of /oauth/token
		op.WithCustomTokenEndpoint(op.NewEndpoint("token")),
		// Pass logger
		op.WithLogger(s.logger.WithGroup("oidc")),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create OpenID provider: %w", err)
	}

	return provider, nil
}

// Handler returns the HTTP handler for the OIDC server
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Add custom discovery handler for pretty-printed JSON
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)

	endSessionHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.rememberPostLogoutRedirectCookie(w, r)
		s.provider.ServeHTTP(w, s.withRequestRedirectContext(r))
	})
	mux.Handle("/end_session", endSessionHandler)

	// Intercept /authorize so we can log incoming client_id, redirect_uri, scope for debugging
	// then forward the request to the provider. This avoids modifying provider internals.
	authorizeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prefer query params for GET; for POST try parsing the form as well.
		clientID := requestParameter(r, "client_id")
		redirectURI := requestParameter(r, "redirect_uri")
		scope := requestParameter(r, "scope")

		s.logger.Info("Authorize request received",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"scope", scope,
			"method", r.Method,
			"remote_addr", r.RemoteAddr)

		// Forward to the provider with the enriched context.
		s.provider.ServeHTTP(w, s.withRequestRedirectContext(r))
	})
	mux.Handle("/authorize", authorizeHandler)

	// Add custom login UI handler (both with and without trailing slash)
	loginHandler := s.createLoginHandler()
	mux.Handle("/login", loginHandler)
	mux.Handle("/login/", loginHandler)

	// Add device flow UI handler (both with and without trailing slash)
	deviceHandler := s.createDeviceHandler()
	mux.Handle("/device", deviceHandler)
	mux.Handle("/device/", deviceHandler)

	// Add logout success page
	mux.HandleFunc("/logged-out", s.handleLoggedOut)
	mux.HandleFunc("/logout/success", s.handleLogoutSuccess)

	// Add health check
	mux.HandleFunc("/health", s.handleHealth)

	// Intercept token endpoint to handle device flow manually
	mux.HandleFunc("/token", s.handleTokenRequest)

	// Mount the OpenID Provider handler at root for all other endpoints
	// This handles all standard OIDC endpoints except /token:
	// - /authorize
	// - /userinfo
	// - /jwks
	// - /end_session (now with enhanced session termination)
	// Note: /.well-known/openid-configuration is handled by our custom handler above
	mux.Handle("/", s.provider)
	var oidcHandler http.Handler = mux
	if s.config.EntraID != nil {
		oidcHandler = s.entraIDRouteMiddleware(oidcHandler)
	}
	oidcHandler = createCORSMiddleware(s.config.OIDC.CORS)(oidcHandler)
	baseHandler := s.reverseProxyMiddleware(oidcHandler)

	// Apply middleware in correct order so denied requests are still logged and get CORS headers.
	handler := s.accessFilterMiddleware(baseHandler)
	handler = s.loggingMiddleware(handler)

	prefix := config.IssuerPathPrefix(s.config.OIDC.Issuer)
	if prefix == "" {
		return handler
	}

	rootMux := http.NewServeMux()
	rootMux.Handle(prefix+"/", http.StripPrefix(prefix, handler))
	rootMux.Handle("/", handler)
	return rootMux
}

func requestParameter(r *http.Request, name string) string {
	if r == nil {
		return ""
	}

	value := r.URL.Query().Get(name)
	if value != "" || r.Method != http.MethodPost {
		return value
	}

	_ = r.ParseForm()
	return r.FormValue(name)
}

func (s *Server) withRequestRedirectContext(r *http.Request) *http.Request {
	if r == nil {
		return nil
	}

	ctx := r.Context()
	if redirectURI := requestParameter(r, "redirect_uri"); redirectURI != "" {
		ctx = context.WithValue(ctx, redirectURIContextKey, redirectURI)
	}
	if postLogout := requestParameter(r, "post_logout_redirect_uri"); postLogout != "" {
		ctx = context.WithValue(ctx, postLogoutRedirectURIContextKey, postLogout)
	}
	return r.WithContext(ctx)
}

func (s *Server) ReadOnlyHTTPHandler() http.Handler {
	base := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAllowedReadOnlyHTTPMethod(r.Method) {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if !s.isAllowedReadOnlyHTTPPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		base.ServeHTTP(w, r)
	})
}

func isAllowedReadOnlyHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func (s *Server) isAllowedReadOnlyHTTPPath(path string) bool {
	canonicalPath, ok := s.readOnlyHTTPCanonicalPath(path)
	if !ok {
		return false
	}
	switch canonicalPath {
	case "/.well-known/openid-configuration", "/keys", "/health":
		return true
	default:
		return false
	}
}

func (s *Server) readOnlyHTTPCanonicalPath(path string) (string, bool) {
	prefix := config.IssuerPathPrefix(s.config.OIDC.Issuer)
	if prefix != "" {
		switch {
		case path == prefix:
			path = "/"
		case strings.HasPrefix(path, prefix+"/"):
			path = strings.TrimPrefix(path, prefix)
		}
	}

	switch path {
	case "/.well-known/openid-configuration", "/keys", "/health":
		return path, true
	}

	route, matched, err := matchEntraIDRoute(path, s.config.EntraID)
	if err != nil || !matched {
		return "", false
	}
	return route.CanonicalPath, true
}

func rewriteRequestPath(r *http.Request, path string) *http.Request {
	clone := r.Clone(r.Context())
	urlCopy := *r.URL
	urlCopy.Path = path
	urlCopy.RawPath = path
	clone.URL = &urlCopy
	clone.RequestURI = ""
	return clone
}

// createLoginHandler creates the login UI handler
func (s *Server) createLoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract auth request ID from query parameters
		authRequestID := r.URL.Query().Get("authRequestID")
		if authRequestID == "" {
			http.Error(w, "Missing authRequestID", http.StatusBadRequest)
			return
		}

		// Get the auth request from storage
		ctx := r.Context()
		authReq, err := s.storage.AuthRequestByID(ctx, authRequestID)
		if err != nil {
			http.Error(w, "Invalid auth request", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			// Show login form
			s.renderLoginForm(w, authRequestID, authReq)
		case http.MethodPost:
			// Process login
			s.processLogin(w, r, authRequestID, authReq)
		}
	})
}

// createDeviceHandler creates the device flow UI handler
func (s *Server) createDeviceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.renderDeviceForm(w, r)
		case http.MethodPost:
			s.processDeviceVerification(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// renderLoginForm renders the user selection/login form using shared template
func (s *Server) renderLoginForm(w http.ResponseWriter, authRequestID string, authReq op.AuthRequest) {
	loginPageConfig := LoginPageConfig{
		AuthRequestID: authRequestID,
		ClientID:      authReq.GetClientID(),
		Scopes:        append([]string(nil), authReq.GetScopes()...),
	}
	if loginUI := s.config.OIDC.LoginUI; loginUI != nil {
		loginPageConfig.EnvironmentTitle = loginUI.EnvTitle
		loginPageConfig.AccentColor = loginUI.EffectiveAccentColor()
		loginPageConfig.HeaderTextColor = loginUI.EffectiveTextColor()
		infoPanelHTML, err := s.renderLoginInfoPanel(loginUI)
		if err != nil {
			s.logger.Warn("Failed to render login info markdown", "error", err, "path", loginUI.EffectiveInfoMarkdownFile())
			loginPageConfig.InfoPanelHTML = renderLoginInfoWarning("Environment notes are currently unavailable.")
		} else {
			loginPageConfig.InfoPanelHTML = infoPanelHTML
		}
	}

	s.renderLoginPage(w, loginPageConfig)
}

// processLogin processes the login form submission
func (s *Server) processLogin(w http.ResponseWriter, r *http.Request, authRequestID string, authReq op.AuthRequest) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	userID := r.FormValue("userID")
	if userID == "" {
		http.Error(w, "No user selected", http.StatusBadRequest)
		return
	}

	// Verify user exists in config
	if _, exists := s.config.Users[userID]; !exists {
		http.Error(w, "Invalid user", http.StatusBadRequest)
		return
	}

	// Complete the auth request with the selected user
	ctx := r.Context()
	if err := s.storage.CompleteAuthRequest(ctx, authRequestID, userID); err != nil {
		s.logger.Error("Failed to complete auth request", "error", err, "authRequestID", authRequestID)
		http.Error(w, "Failed to complete authentication", http.StatusInternalServerError)
		return
	}

	// Generate authorization code
	authCode := generateAuthCode()
	if err := s.storage.SaveAuthCode(ctx, authRequestID, authCode); err != nil {
		s.logger.Error("Failed to save auth code", "error", err, "authRequestID", authRequestID)
		http.Error(w, "Failed to save authorization code", http.StatusInternalServerError)
		return
	}

	// Build redirect URL to client with authorization code
	redirectURI := authReq.GetRedirectURI()
	state := authReq.GetState()

	// Use response mode to determine how to send the response
	responseMode := authReq.GetResponseMode()
	if responseMode == "" {
		responseMode = "query" // Default to query mode
	}

	var finalRedirectURL string
	if strings.ToLower(string(responseMode)) == "fragment" {
		// Fragment mode (for SPAs)
		finalRedirectURL = fmt.Sprintf("%s#code=%s&state=%s", redirectURI, authCode, state)
	} else {
		// Query mode (default)
		separator := "?"
		if strings.Contains(redirectURI, "?") {
			separator = "&"
		}
		finalRedirectURL = fmt.Sprintf("%s%scode=%s&state=%s", redirectURI, separator, authCode, state)
	}

	s.logger.Info("Authorization successful",
		"user", userID,
		"client", authReq.GetClientID(),
		"redirect_uri", redirectURI,
		"response_mode", responseMode)

	http.Redirect(w, r, finalRedirectURL, http.StatusFound)
}

// generateAuthCode generates a random authorization code
func generateAuthCode() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 32

	b := make([]byte, length)
	randBytes := make([]byte, length)
	rand.Read(randBytes)

	for i := range b {
		b[i] = charset[randBytes[i]%byte(len(charset))]
	}
	return string(b)
}

// renderDeviceForm renders the device verification form
func (s *Server) renderDeviceForm(w http.ResponseWriter, r *http.Request) {
	// Get user code from query parameter if provided
	userCode := r.URL.Query().Get("user_code")

	// Create the HTML form with pre-filled user code if available
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Verification - OIDC Test Identity Provider</title>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { text-align: center; }
        input[type="text"] { padding: 15px; font-size: 18px; width: 300px; text-align: center; letter-spacing: 2px; font-family: monospace; }
        button { background-color: #007bff; color: white; border: none; padding: 15px 30px; border-radius: 5px; cursor: pointer; font-size: 16px; margin-left: 10px; }
        button:hover { background-color: #0056b3; }
        .user-list { list-style: none; padding: 0; margin-top: 30px; }
        .user-button { 
            display: block; 
            width: 100%%; 
            margin: 10px 0; 
            padding: 15px; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            background: white; 
            cursor: pointer; 
            text-align: left;
            font-size: 16px;
        }
        .user-button:hover { background-color: #f5f5f5; }
        .user-button:focus { outline: 2px solid #007bff; outline-offset: 2px; }
        .user-name { font-weight: bold; display: block; }
        .user-email { color: #666; font-size: 0.9em; display: block; margin-top: 4px; }
        .code-display { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Device Verification</h1>
        <p>Enter the code displayed on your device:</p>
        
        <form method="POST">
            <input type="text" name="user_code" value="%s" placeholder="XXXX-XXXX" required maxlength="9" style="text-transform: uppercase;">
			<button type="submit">Verify Device</button>
			<button onclick="denyDevice()" style="background-color: #dc3545; margin-top: 20px;">Deny Authorization</button>
		</div>
	</div>

	<script>
        // Auto-focus on the input field
        document.querySelector('input[name="user_code"]').focus();
        
        // Auto-uppercase input
        document.querySelector('input[name="user_code"]').addEventListener('input', function(e) {
            e.target.value = e.target.value.toUpperCase();
        });
        
        function authorizeDevice(userID, userCode) {
            fetch('/device', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'user_code=' + encodeURIComponent(userCode) + '&user_id=' + encodeURIComponent(userID) + '&action=approve'
            })
            .then(response => response.text())
            .then(data => {
                document.body.innerHTML = '<div class="container"><h1>✅ Device Authorized</h1><p>You can now close this window and return to your device.</p></div>';
            })
            .catch(error => {
                alert('Error: ' + error);
            });
        }
        
        function denyDevice() {
            const userCode = document.querySelector('input[name="user_code"]').value;
            fetch('/device', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'user_code=' + encodeURIComponent(userCode) + '&action=deny'
            })
            .then(response => response.text())
            .then(data => {
                document.body.innerHTML = '<div class="container"><h1>❌ Device Authorization Denied</h1><p>You can now close this window.</p></div>';
            })
            .catch(error => {
                alert('Error: ' + error);
            });
        }
    </script>
</body>

</html>`, html.EscapeString(userCode))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleLoggedOut handles the logout success page
func (s *Server) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	s.showLogoutSuccessPage(w, r)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"oidcld","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// getEmailFromClaims extracts email from user claims
func getEmailFromClaims(claims map[string]any) string {
	if email, ok := claims["email"].(string); ok {
		return email
	}
	return ""
}

// Start starts the OIDC server
func (s *Server) Start(port string) error {
	addr := fmt.Sprintf(":%s", port)

	server := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	s.prettyLog.ServerStarting(s.startupSummary(false, "none"))
	return server.ListenAndServe()
}

// StartTLS starts the OIDC server with TLS
func (s *Server) StartTLS(port, certFile, keyFile string) error {
	return s.startTLS(port, certFile, keyFile, true)
}

func (s *Server) startTLS(port, certFile, keyFile string, logStartup bool) error {
	addr := fmt.Sprintf(":%s", port)

	server := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	// If autocert manager is configured, prefer it when no cert/key provided.
	if s.autocertManager != nil {
		// If both autocert and explicit cert/key are provided, that's ambiguous — error out.
		if certFile != "" || keyFile != "" {
			return ErrAutocertConflictTLSProvided
		}

		if logStartup {
			s.prettyLog.ServerStarting(s.startupSummary(true, "acme"))
		}

		// Use autocert TLSConfig and let the standard library's ListenAndServeTLS
		// drive certificate obtains during TLS handshakes. This matches the
		// myencrypt example: TLSConfig provides GetCertificate and autocert will
		// obtain certificates on-demand during incoming connections.
		server.TLSConfig = s.autocertManager.GetTLSConfig()

		// Start HTTPS server; autocert's GetCertificate will perform obtains as
		// necessary. We call ListenAndServeTLS with empty cert/key so the TLSConfig
		// is used.
		return server.ListenAndServeTLS("", "")
	}

	if (certFile == "") != (keyFile == "") {
		return ErrManualTLSCertificateKeyRequired
	}

	if certFile == "" && keyFile == "" {
		tlsConfig, err := s.buildListenerTLSConfig("", "")
		if err != nil {
			return err
		}
		server.TLSConfig = tlsConfig
		if logStartup {
			s.prettyLog.ServerStarting(s.startupSummary(true, "self-signed"))
		}
		return server.ListenAndServeTLS("", "")
	}

	tlsConfig, err := s.buildListenerTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	server.TLSConfig = tlsConfig

	if logStartup {
		s.prettyLog.ServerStarting(s.startupSummary(true, "manual"))
	}

	return server.ListenAndServeTLS("", "")
}

func (s *Server) startupSummary(tlsEnabled bool, tlsSource string) startupSummary {
	endpoints, tenants := startupEndpointsForIssuer(s.config.OIDC.Issuer, s.config.EntraID)
	summary := startupSummary{
		OIDC: startupOIDCSummary{
			Mode:         startupModeLabel(s.config.EntraID),
			TLSEnabled:   tlsEnabled,
			TLSSource:    tlsSource,
			AccessFilter: formatAccessFilterStartupInfo(s.access.startupInfo()),
			Endpoints:    endpoints,
			Tenants:      tenants,
		},
	}

	if s.config.Console != nil {
		summary.DeveloperConsoleURL = ConsoleURL(s.config.Console.BindAddress, s.config.Console.Port)
		if tlsEnabled {
			httpMetadataAddr := fmt.Sprintf(":%s", strings.TrimSpace(s.config.Console.Port))
			if metadataIssuer := config.HTTPMetadataIssuer(s.config.OIDC.Issuer, httpMetadataAddr); metadataIssuer != "" {
				metadataEndpoints, metadataTenants := startupEndpointsForIssuer(metadataIssuer, s.config.EntraID)
				summary.MetadataCompanion = &startupMetadataSummary{
					Discovery: metadataEndpoints.Discovery,
					JWKS:      metadataEndpoints.JWKS,
					Tenants:   metadataTenants,
				}
			}
		}
	}

	return summary
}

func startupModeLabel(entraid *config.EntraIDConfig) string {
	if entraid == nil {
		return "oidc"
	}
	if strings.EqualFold(entraid.Version, "v1") {
		return "entraid v1"
	}
	return "entraid v2"
}

func formatAccessFilterStartupInfo(info accessFilterStartupInfo) string {
	if !info.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (extra allowlist: %d, max forwarded hops: %d)", info.ExtraAllowedIPs, info.MaxForwardedHops)
}

// UpdateConfig updates the server configuration at runtime
func (s *Server) UpdateConfig(newConfig *config.Config) error {
	// Validate the new configuration
	if newConfig == nil {
		return ErrConfigurationCannotBeNil
	}
	if err := newConfig.Normalize(); err != nil {
		return err
	}

	// Validate issuer hasn't changed (would require server restart)
	if s.config.OIDC.Issuer != newConfig.OIDC.Issuer {
		return fmt.Errorf("%w: old=%s, new=%s",
			ErrIssuerURLCannotBeChanged, s.config.OIDC.Issuer, newConfig.OIDC.Issuer)
	}

	// Track changes for colorful logging
	var changes []string

	// Check for user changes
	if len(s.config.Users) != len(newConfig.Users) {
		changes = append(changes, fmt.Sprintf("Users: %d → %d", len(s.config.Users), len(newConfig.Users)))
	}

	// Check for scope changes
	if len(s.config.OIDC.ValidScopes) != len(newConfig.OIDC.ValidScopes) {
		changes = append(changes, fmt.Sprintf("Valid Scopes: %d → %d", len(s.config.OIDC.ValidScopes), len(newConfig.OIDC.ValidScopes)))
	}

	// Check token expiration changes
	if s.config.OIDC.ExpiredIn != newConfig.OIDC.ExpiredIn {
		changes = append(changes, fmt.Sprintf("Token Expiry: %ds → %ds", s.config.OIDC.ExpiredIn, newConfig.OIDC.ExpiredIn))
	}

	// Check refresh token settings
	if s.config.OIDC.RefreshTokenEnabled != newConfig.OIDC.RefreshTokenEnabled {
		changes = append(changes, fmt.Sprintf("Refresh Tokens: %v → %v", s.config.OIDC.RefreshTokenEnabled, newConfig.OIDC.RefreshTokenEnabled))
	}
	if s.config.AccessFilter.Enabled != newConfig.AccessFilter.Enabled {
		changes = append(changes, fmt.Sprintf("Access Filter Enabled: %v → %v", s.config.AccessFilter.Enabled, newConfig.AccessFilter.Enabled))
	}
	if s.config.AccessFilter.MaxForwardedHops != newConfig.AccessFilter.MaxForwardedHops {
		changes = append(changes, fmt.Sprintf("Access Filter Max Forwarded Hops: %d → %d", s.config.AccessFilter.MaxForwardedHops, newConfig.AccessFilter.MaxForwardedHops))
	}
	if !slices.Equal(s.config.AccessFilter.ExtraAllowedIPs, newConfig.AccessFilter.ExtraAllowedIPs) {
		changes = append(changes, fmt.Sprintf("Access Filter Extra Allowed IPs: %d → %d", len(s.config.AccessFilter.ExtraAllowedIPs), len(newConfig.AccessFilter.ExtraAllowedIPs)))
	}

	compiledAccess, err := newCompiledAccessFilter(newConfig.AccessFilter)
	if err != nil {
		return err
	}
	compiledReverseProxy, err := newCompiledReverseProxy(newConfig)
	if err != nil {
		return err
	}

	// Update the configuration atomically
	s.config = newConfig
	s.access = compiledAccess
	s.reverseProxy = compiledReverseProxy
	s.reverseProxyLog = newReverseProxyLogStore(reverseProxyLogRetention(newConfig))
	s.managedLeaves = map[string]*managedLeafCertificate{}

	// Update storage adapter configuration
	s.storage.UpdateConfig(newConfig)

	// Log the successful reload with colorful output
	s.prettyLog.ConfigReloaded("configuration", changes)

	return nil
}

// GetPrettyLogger returns the colorful logger for external use
func (s *Server) GetPrettyLogger() *Logger {
	return s.prettyLog
}

// loggingMiddleware provides colorful HTTP request logging with CORS debugging info
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code and headers
		wrapper := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Call the next handler
		next.ServeHTTP(wrapper, r)

		// Log the request with colorful output, but avoid noisy health probe
		// access logs unless verbose logging is explicitly enabled in config.
		duration := time.Since(start)

		// Health probes are intentionally silent to avoid access-log noise.
		if r.URL != nil && r.URL.Path == "/health" && wrapper.reverseProxy == nil {
			return
		}

		// Check for CORS-related information for debugging
		origin := r.Header.Get("Origin")
		corsOrigin := wrapper.Header().Get("Access-Control-Allow-Origin")

		// Enhanced logging with CORS info when relevant
		if origin != "" || corsOrigin != "" {
			s.prettyLog.RequestLogWithCORS(r.Method, r.URL.Path, wrapper.statusCode, duration, origin, corsOrigin)
		} else {
			s.prettyLog.RequestLog(r.Method, r.URL.Path, wrapper.statusCode, duration)
		}
		logMeta := wrapper.reverseProxy
		if logMeta == nil {
			logMeta = s.oidcTrafficLogMeta(r)
		}
		if logMeta != nil && s.reverseProxyLog != nil {
			logHost := strings.TrimSpace(r.Host)
			if logHost == "" && r.URL != nil {
				logHost = strings.TrimSpace(r.URL.Host)
			}
			s.reverseProxyLog.Add(reverseProxyLogEntry{
				Timestamp:  time.Now().UTC(),
				Host:       logHost,
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: wrapper.statusCode,
				DurationMS: duration.Milliseconds(),
				Bytes:      wrapper.bytesWritten,
				RouteType:  logMeta.RouteType,
				RouteHost:  logMeta.RouteHost,
				RoutePath:  logMeta.RoutePath,
				RouteLabel: logMeta.RouteLabel,
				Target:     logMeta.Target,
				RemoteAddr: r.RemoteAddr,
			})
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter

	statusCode   int
	bytesWritten int
	reverseProxy *reverseProxyLogMeta
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(data)
	rw.bytesWritten += n
	return n, err
}

func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := rw.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

// handleDiscovery provides a custom discovery endpoint with pretty-printed JSON
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	// Get the discovery configuration from the provider
	issuer := s.provider.IssuerFromRequest(r)
	requestInfo := entraIDRequestInfoFromRequest(r)
	endpoints := discoveryEndpointsForRequest(issuer, s.config.EntraID, requestInfo)

	// Create the discovery document
	discovery := map[string]any{
		"issuer":                                                   issuer,
		"authorization_endpoint":                                   endpoints.Authorize,
		"token_endpoint":                                           endpoints.Token,
		"introspection_endpoint":                                   endpoints.Introspection,
		"userinfo_endpoint":                                        endpoints.UserInfo,
		"revocation_endpoint":                                      endpoints.Revocation,
		"end_session_endpoint":                                     endpoints.Logout,
		"device_authorization_endpoint":                            endpoints.DeviceAuthorization,
		"jwks_uri":                                                 endpoints.JWKS,
		"scopes_supported":                                         []string{"openid", "profile", "email", "phone", "address", "offline_access"},
		"response_types_supported":                                 []string{"code", "id_token", "id_token token"},
		"grant_types_supported":                                    []string{"authorization_code", "implicit", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:device_code"},
		"subject_types_supported":                                  []string{"public"},
		"id_token_signing_alg_values_supported":                    []string{"RS256"},
		"request_object_signing_alg_values_supported":              []string{"RS256"},
		"token_endpoint_auth_methods_supported":                    []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported":         []string{"RS256"},
		"revocation_endpoint_auth_methods_supported":               []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"revocation_endpoint_auth_signing_alg_values_supported":    []string{"RS256"},
		"introspection_endpoint_auth_methods_supported":            []string{"client_secret_basic", "private_key_jwt"},
		"introspection_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                                         []string{"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "acr", "amr", "c_hash", "at_hash", "act", "scopes", "client_id", "azp", "preferred_username", "name", "family_name", "given_name", "locale", "email", "email_verified", "phone_number", "phone_number_verified"},
		"ui_locales_supported":                                     []string{"en"},
		"request_parameter_supported":                              true,
		"request_uri_parameter_supported":                          false,
	}

	// Add conditional endpoints based on configuration
	if s.config.OIDC.EndSessionEnabled && s.config.OIDC.EndSessionEndpointVisible {
		// end_session_endpoint is already included above
	} else if !s.config.OIDC.EndSessionEnabled {
		delete(discovery, "end_session_endpoint")
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Encode with pretty printing (indentation)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(discovery); err != nil {
		http.Error(w, "Failed to encode discovery document", http.StatusInternalServerError)
		return
	}
}

// processDeviceVerification handles device verification form submission
func (s *Server) processDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	userCode := r.FormValue("user_code")
	userID := r.FormValue("user_id")
	action := r.FormValue("action")

	if userCode == "" {
		// First step: verify user code and show user selection
		http.Error(w, "User code is required", http.StatusBadRequest)
		return
	}

	// Check if user code exists
	s.storage.lock.Lock()
	_, exists := s.storage.userCodeToDevice[userCode]
	s.storage.lock.Unlock()

	if !exists {
		// Invalid user code - show error
		html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Invalid Code - OIDC Test Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <h1 class="error">❌ Invalid Device Code</h1>
    <p>The code you entered is not valid or has expired.</p>
    <p><a href="/device">Try Again</a></p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	if action == "approve" && userID != "" {
		// Complete device authorization with approval
		if err := s.storage.CompleteDeviceAuthorization(userCode, userID, true); err != nil {
			http.Error(w, "Failed to authorize device: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Success response
		html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>📺 Device Authorized - OIDC Test Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <h1 class="success">✅ Device Authorized Successfully</h1>
    <p>You can now close this window and return to your device.</p>
    <p>Your device should now have access to the requested resources.</p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	} else if action == "deny" {
		// Complete device authorization with denial
		if err := s.storage.CompleteDeviceAuthorization(userCode, "", false); err != nil {
			http.Error(w, "Failed to deny device: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Denial response
		html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Device Authorization Denied - OIDC Test Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .warning { color: #ffc107; }
    </style>
</head>
<body>
    <h1 class="warning">❌ Device Authorization Denied</h1>
    <p>You have denied access to this device.</p>
    <p>You can now close this window.</p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	} else {
		// Show user selection form using shared template
		config := UserSelectionConfig{
			Title: "Authorize Device",
			Description: fmt.Sprintf(`
            <p>A device is requesting access with the code:</p>
            <div class="code-display">%s</div>
            <p>Select a user to authorize this device:</p>`, userCode),
			HiddenFields: map[string]string{
				"user_code": userCode,
			},
			ButtonAction: "authorizeDevice",
			ExtraHTML:    fmt.Sprintf(`<button onclick="denyDevice('%s')" class="deny-button">Deny Authorization</button>`, userCode),
			ExtraScript: `
    <script>
        function authorizeDevice(userID, userCode) {
            fetch('/device', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'user_code=' + encodeURIComponent(userCode) + '&user_id=' + encodeURIComponent(userID) + '&action=approve'
            })
            .then(response => response.text())
            .then(data => {
                document.body.innerHTML = data;
            })
            .catch(error => {
                alert('Error: ' + error);
            });
        }
        
        function denyDevice(userCode) {
            fetch('/device', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'user_code=' + encodeURIComponent(userCode) + '&action=deny'
            })
            .then(response => response.text())
            .then(data => {
                document.body.innerHTML = data;
            })
            .catch(error => {
                alert('Error: ' + error);
            });
        }
    </script>`,
		}

		s.renderSharedUserSelectionPage(w, config)
	}
}

// signJWT signs a JWT token with the server's private key
func (s *Server) signJWT(claims jwt.MapClaims) (string, error) {
	jwtAudienceClaimFormatMu.Lock()
	configureJWTAudienceClaimFormat(s.config.OIDC.NormalizedAudienceClaimFormat())
	defer jwtAudienceClaimFormatMu.Unlock()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set key ID header
	token.Header["kid"] = deriveSigningKeyID(s.privateKey)

	return token.SignedString(s.privateKey)
}

func normalizeAudienceClaimValue(value any, format string) (any, bool) {
	switch aud := value.(type) {
	case string:
		if format == config.AudienceClaimFormatArray {
			return []string{aud}, true
		}
	case []string:
		if len(aud) == 1 && format == config.AudienceClaimFormatString {
			return aud[0], true
		}
	case jwt.ClaimStrings:
		if len(aud) == 1 && format == config.AudienceClaimFormatString {
			return aud[0], true
		}
	case []any:
		if len(aud) == 1 {
			singleAudience, ok := aud[0].(string)
			if !ok {
				return value, false
			}
			if format == config.AudienceClaimFormatString {
				return singleAudience, true
			}
		}
	}

	return value, false
}

func (s *Server) rewriteJWTTokenAudience(token string) (string, error) {
	if token == "" || strings.Count(token, ".") != 2 {
		return token, nil
	}

	claims := jwt.MapClaims{}
	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	normalizedAudience, changed := normalizeAudienceClaimValue(claims["aud"], s.config.OIDC.NormalizedAudienceClaimFormat())
	if !changed {
		return token, nil
	}

	claims["aud"] = normalizedAudience

	rewrittenToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	for key, value := range parsedToken.Header {
		if key == "alg" {
			continue
		}
		rewrittenToken.Header[key] = value
	}
	if _, ok := rewrittenToken.Header["kid"]; !ok {
		rewrittenToken.Header["kid"] = deriveSigningKeyID(s.privateKey)
	}

	return rewrittenToken.SignedString(s.privateKey)
}

func (s *Server) normalizeTokenResponsePayload(payload map[string]any) error {
	for _, field := range []string{"access_token", "id_token", "refresh_token"} {
		tokenValue, ok := payload[field].(string)
		if !ok || tokenValue == "" {
			continue
		}

		rewrittenToken, err := s.rewriteJWTTokenAudience(tokenValue)
		if err != nil {
			return fmt.Errorf("failed to rewrite %s: %w", field, err)
		}
		payload[field] = rewrittenToken
	}

	return nil
}

func copyResponseHeaders(dst, src http.Header) {
	for key := range dst {
		dst.Del(key)
	}
	for key, values := range src {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (s *Server) writeTokenJSONResponse(w http.ResponseWriter, statusCode int, headers http.Header, payload map[string]any) error {
	if err := s.normalizeTokenResponsePayload(payload); err != nil {
		return err
	}

	if headers != nil {
		copyResponseHeaders(w.Header(), headers)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)

	return json.NewEncoder(w).Encode(payload)
}

func (s *Server) serveProviderTokenResponse(w http.ResponseWriter, r *http.Request) {
	recorder := httptest.NewRecorder()
	s.provider.ServeHTTP(recorder, r)

	result := recorder.Result()
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		s.logger.Error("Failed to read provider token response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if result.StatusCode < http.StatusOK || result.StatusCode >= http.StatusMultipleChoices {
		copyResponseHeaders(w.Header(), result.Header)
		w.WriteHeader(result.StatusCode)
		_, _ = w.Write(body)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		copyResponseHeaders(w.Header(), result.Header)
		w.WriteHeader(result.StatusCode)
		_, _ = w.Write(body)
		return
	}

	if err := s.writeTokenJSONResponse(w, result.StatusCode, result.Header, payload); err != nil {
		s.logger.Error("Failed to normalize provider token response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// writeTokenError writes an OAuth 2.0 token error response
func (s *Server) writeTokenError(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusBadRequest)

	errorResponse := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}

	json.NewEncoder(w).Encode(errorResponse)
}
func (s *Server) generateDeviceFlowTokens(clientID, userID string, user config.User, scopes []string) (accessToken, idToken, refreshToken string, err error) {
	now := time.Now()
	expiry := now.Add(time.Duration(s.config.OIDC.ExpiredIn) * time.Second)

	accessTokenClaims := s.buildDeviceFlowAccessTokenClaims(clientID, userID, user, scopes, now, expiry)
	accessToken, err = s.signJWT(accessTokenClaims)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	if slices.Contains(scopes, "openid") {
		idTokenClaims := s.buildDeviceFlowIDTokenClaims(clientID, userID, user, scopes, now, expiry)
		idToken, err = s.signJWT(idTokenClaims)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	if s.config.OIDC.RefreshTokenEnabled {
		refreshExpiry := now.Add(time.Duration(s.config.OIDC.RefreshTokenExpiry) * time.Second)
		refreshTokenClaims := s.buildDeviceFlowRefreshTokenClaims(clientID, userID, scopes, now, refreshExpiry)
		refreshToken, err = s.signJWT(refreshTokenClaims)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to sign refresh token: %w", err)
		}
	}

	return accessToken, idToken, refreshToken, nil
}
func (s *Server) handleDeviceFlowTokenRequest(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")

	if deviceCode == "" {
		s.writeTokenError(w, "invalid_request", "device_code is required")
		return
	}

	if clientID == "" {
		s.writeTokenError(w, "invalid_request", "client_id is required")
		return
	}

	// In test/permissive mode we do not validate client against configured audiences here.
	// The StorageAdapter is responsible for client validation; for testing we accept any client.

	// Get device authorization from storage
	s.storage.lock.Lock()
	deviceAuth, exists := s.storage.deviceAuthorizations[deviceCode]
	if !exists {
		s.storage.lock.Unlock()
		s.writeTokenError(w, "invalid_grant", "invalid or expired device_code")
		return
	}

	// Check if device is authorized
	if !deviceAuth.Done {
		s.storage.lock.Unlock()
		s.writeTokenError(w, "authorization_pending", "The client SHOULD repeat the access token request to the token endpoint, after interval from device authorization response.")
		return
	}

	// Check if device was denied
	if deviceAuth.Denied {
		s.storage.lock.Unlock()
		s.writeTokenError(w, "access_denied", "The end user denied the authorization request")
		return
	}

	// Check if device code is expired
	if time.Now().After(deviceAuth.Expires) {
		// Clean up expired device code
		delete(s.storage.deviceAuthorizations, deviceCode)
		delete(s.storage.userCodeToDevice, deviceAuth.UserCode)
		s.storage.lock.Unlock()
		s.writeTokenError(w, "expired_token", "device_code has expired")
		return
	}

	// Get user information
	user, exists := s.config.Users[deviceAuth.Subject]
	if !exists {
		s.storage.lock.Unlock()
		s.writeTokenError(w, "invalid_grant", "invalid user")
		return
	}

	// Clean up used device code (one-time use)
	delete(s.storage.deviceAuthorizations, deviceCode)
	delete(s.storage.userCodeToDevice, deviceAuth.UserCode)
	s.storage.lock.Unlock()

	// Generate tokens manually
	accessToken, idToken, refreshToken, err := s.generateDeviceFlowTokens(clientID, deviceAuth.Subject, user, deviceAuth.Scopes)
	if err != nil {
		s.logger.Error("Failed to generate device flow tokens", "error", err)
		s.writeTokenError(w, "server_error", "Failed to generate tokens")
		return
	}

	// Build token response
	tokenResponse := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   s.config.OIDC.ExpiredIn,
		"id_token":     idToken,
		"scope":        strings.Join(deviceAuth.Scopes, " "),
	}

	// Add refresh token if enabled
	if s.config.OIDC.RefreshTokenEnabled && refreshToken != "" {
		tokenResponse["refresh_token"] = refreshToken
	}

	if err := s.writeTokenJSONResponse(w, http.StatusOK, nil, tokenResponse); err != nil {
		s.logger.Error("Failed to encode token response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	s.logger.Info("Device flow token issued", "client_id", clientID, "user_id", deviceAuth.Subject)
}
func (s *Server) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Only intercept POST requests to /token
	if r.Method != http.MethodPost {
		s.provider.ServeHTTP(w, r)
		return
	}

	// Parse form to check grant type
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	jwtAudienceClaimFormatMu.Lock()
	configureJWTAudienceClaimFormat(s.config.OIDC.NormalizedAudienceClaimFormat())
	jwtAudienceClaimFormatMu.Unlock()
	// If the token request includes a redirect_uri (authorization_code flow),
	// inject it into the request context so storage.GetClientByClientID can
	// return a client that permits that exact redirect URI for validation.
	if redirectURI := r.FormValue("redirect_uri"); redirectURI != "" {
		ctx := r.Context()
		ctx = context.WithValue(ctx, redirectURIContextKey, redirectURI)
		r = r.WithContext(ctx)
	}

	grantType := r.FormValue("grant_type")

	// Log client_id and scopes for debugging invalid_scope errors
	clientID := r.FormValue("client_id")
	scopesStr := r.FormValue("scope")
	var scopesList []string
	if scopesStr != "" {
		for s := range strings.SplitSeq(scopesStr, " ") {
			s = strings.TrimSpace(s)
			if s != "" {
				scopesList = append(scopesList, s)
			}
		}
	}

	s.logger.Info("Token request received",
		"client_id", clientID,
		"grant_type", grantType,
		"scopes", scopesList)

	// If we can obtain a client from storage, check which scopes are not allowed
	if clientID != "" {
		if cli, err := s.storage.GetClientByClientID(r.Context(), clientID); err == nil && cli != nil {
			var disallowed []string
			for _, sc := range scopesList {
				if !cli.IsScopeAllowed(sc) {
					disallowed = append(disallowed, sc)
				}
			}
			if len(disallowed) > 0 {
				s.prettyLog.Warning(fmt.Sprintf("Token request contains disallowed scopes: %v", disallowed))
			}
		}
	}

	// Handle device flow token requests manually
	if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
		s.handleDeviceFlowTokenRequest(w, r)
		return
	}

	// For all other grant types, use zitadel/oidc default logic
	s.serveProviderTokenResponse(w, r)
}

type UserSelectionConfig struct {
	Title        string
	Description  string
	FormAction   string
	HiddenFields map[string]string
	ButtonAction string // "submit" for form submission, or JavaScript function name
	ExtraHTML    string // Additional HTML to append (like deny button)
	ExtraScript  string // Additional JavaScript
}

// renderSharedUserSelectionPage renders a shared user selection page for both auth code flow and device flow
func (s *Server) renderSharedUserSelectionPage(w http.ResponseWriter, config UserSelectionConfig) {
	var builder strings.Builder
	fmt.Fprintf(&builder, `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - OIDC Test Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .container { text-align: center; }
        .user-list { list-style: none; padding: 0; margin-top: 30px; }
        .user-button { 
            display: block; 
            width: 100%%; 
            margin: 10px 0; 
            padding: 15px; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            background: white; 
            cursor: pointer; 
            text-align: left;
            font-size: 16px;
        }
        .user-button:hover { background-color: #f5f5f5; }
        .user-button:focus { outline: 2px solid #007bff; outline-offset: 2px; }
        .user-name { font-weight: bold; display: block; }
        .user-email { color: #666; font-size: 0.9em; display: block; margin-top: 4px; }
        .client-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .code-display { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; font-family: monospace; font-size: 24px; letter-spacing: 3px; }
        .deny-button { background-color: #dc3545; color: white; border: none; padding: 15px 30px; border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 20px; }
        .deny-button:hover { background-color: #c82333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>%s</h1>
        %s
        
        <ul class="user-list">`, config.Title, config.Title, config.Description)

	// Add user selection buttons with aria-labels for E2E testing
	for userID, user := range s.config.Users {
		email := getEmailFromClaims(user.ExtraClaims)

		if config.ButtonAction == "submit" {
			// For auth code flow - form submission
			fmt.Fprintf(&builder, `
            <li>
                <form method="POST" action="%s" style="display: inline-block; width: 100%%;">`, config.FormAction)

			// Add hidden fields
			for name, value := range config.HiddenFields {
				fmt.Fprintf(&builder, `
                    <input type="hidden" name="%s" value="%s">`, name, value)
			}

			fmt.Fprintf(&builder, `
                    <button type="submit" name="userID" value="%s" class="user-button" aria-label="%s">
                        <span class="user-name">%s</span>
                        <span class="user-email">%s</span>
                    </button>
                </form>
            </li>`, userID, userID, user.DisplayName, email)
		} else {
			// For device flow - JavaScript action
			actionParams := ""
			for name, value := range config.HiddenFields {
				if name == "user_code" {
					actionParams = fmt.Sprintf("'%s', '%s'", userID, value)
					break
				}
			}

			fmt.Fprintf(&builder, `
            <li>
                <button type="button" onclick="%s(%s)" class="user-button" aria-label="%s">
                    <span class="user-name">%s</span>
                    <span class="user-email">%s</span>
                </button>
            </li>`, config.ButtonAction, actionParams, userID, user.DisplayName, email)
		}
	}

	fmt.Fprintf(&builder, `
        </ul>
        %s
    </div>
    %s
</body>
</html>`, config.ExtraHTML, config.ExtraScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(builder.String()))
}
