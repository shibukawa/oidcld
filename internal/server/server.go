package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	// "log" was removed (diagnostic logs cleaned up)

	// ...existing code...
	"encoding/json"
	"fmt"
	"html"
	"log/slog"

	// ...existing code...
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

var (
	ErrConfigurationCannotBeNil        = fmt.Errorf("configuration cannot be nil")
	ErrIssuerURLCannotBeChanged        = fmt.Errorf("issuer URL cannot be changed at runtime")
	ErrSigningAlgorithmCannotBeChanged = fmt.Errorf("signing algorithm cannot be changed at runtime")
)

// Server represents the new zitadel/oidc-based server implementation
type Server struct {
	config     *config.Config
	storage    *StorageAdapter
	provider   op.OpenIDProvider
	privateKey *rsa.PrivateKey
	logger     *slog.Logger
	prettyLog  *Logger // Add colorful logger

	// Autocert manager (optional)
	autocertManager *AutocertManager
	autocertCtx     context.Context
	autocertCancel  context.CancelFunc
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
	// Create storage adapter
	storage := NewStorageAdapter(cfg, privateKey)

	// Create the server instance
	server := &Server{
		config:     cfg,
		storage:    storage,
		privateKey: privateKey,
		logger:     logger,
		prettyLog:  NewLogger(), // Initialize colorful logger
	}

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
		ctx, cancel := context.WithCancel(context.Background())
		server.autocertManager = am
		server.autocertCtx = ctx
		server.autocertCancel = cancel

		// The renewal monitor is now handled via RenewBefore, so we do not start it here.
	}

	return server, nil
}

// createProvider creates the zitadel OpenID Provider with proper configuration
func (s *Server) createProvider() (op.OpenIDProvider, error) {
	// Create encryption key for tokens (32 bytes required)
	key := sha256.Sum256([]byte("oidcld-encryption-key-" + s.config.OIDCLD.Issuer))

	// Configure the OpenID Provider
	config := &op.Config{
		CryptoKey: key,

		// Default logout redirect URI
		DefaultLogoutRedirectURI: "/logged-out",

		// Enable PKCE with S256
		CodeMethodS256: s.config.OIDCLD.PKCERequired,

		// Enable form post authentication (in addition to HTTP Basic Auth)
		AuthMethodPost: true,

		// Enable private key JWT authentication
		AuthMethodPrivateKeyJWT: true,

		// Enable refresh token grant
		GrantTypeRefreshToken: s.config.OIDCLD.RefreshTokenEnabled,

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
	issuer := s.config.OIDCLD.Issuer
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

	// Intercept /authorize so we can log incoming client_id, redirect_uri, scope for debugging
	// then forward the request to the provider. This avoids modifying provider internals.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Prefer query params for GET; for POST try parsing the form as well.
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		scope := r.URL.Query().Get("scope")

		if r.Method == http.MethodPost {
			// Try parsing form but ignore errors to avoid interfering with provider handling.
			_ = r.ParseForm()
			if clientID == "" {
				clientID = r.FormValue("client_id")
			}
			if redirectURI == "" {
				redirectURI = r.FormValue("redirect_uri")
			}
			if scope == "" {
				scope = r.FormValue("scope")
			}
		}

		s.logger.Info("Authorize request received",
			"client_id", clientID,
			"redirect_uri", redirectURI,
			"scope", scope,
			"method", r.Method,
			"remote_addr", r.RemoteAddr)

		// Forward to the provider for normal processing
		s.provider.ServeHTTP(w, r)
	})

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

	// Apply middleware in correct order: CORS first (outermost), then logging
	handler := s.loggingMiddleware(mux)
	return createCORSMiddleware(s.config.CORS)(handler)
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
	config := UserSelectionConfig{
		Title: "Select Test User",
		Description: fmt.Sprintf(`
        <div class="client-info">
            <p><strong>Client:</strong> %s</p>
            <p><strong>Scopes:</strong> %s</p>
        </div>`,
			authReq.GetClientID(),
			fmt.Sprintf("%v", authReq.GetScopes())),
		FormAction: "",
		HiddenFields: map[string]string{
			"authRequestID": html.EscapeString(authRequestID),
		},
		ButtonAction: "submit",
	}

	s.renderSharedUserSelectionPage(w, config)
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
func (s *Server) handleLoggedOut(w http.ResponseWriter, _ *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Logged Out - OIDC Test Identity Provider</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <h1 class="success">✓ Successfully Logged Out</h1>
    <p>You have been successfully logged out from the OIDC Test Identity Provider.</p>
    <p>You can now close this window or navigate to your application.</p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// Emit a log line for health probe activity only when verbose logging is enabled.
	if s != nil && s.config != nil && s.config.OIDCLD.VerboseLogging {
		// Use pretty logger if available
		if s.prettyLog != nil {
			s.prettyLog.RequestLog(http.MethodGet, "/health", http.StatusOK, 0)
		} else if s.logger != nil {
			s.logger.Info("health probe received")
		}
	}
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

	// Use colorful logging for server startup
	s.prettyLog.ServerStarting(addr, s.config.OIDCLD.Issuer, false)
	return server.ListenAndServe()
}

// StartTLS starts the OIDC server with TLS
func (s *Server) StartTLS(port, certFile, keyFile string) error {
	addr := fmt.Sprintf(":%s", port)

	server := &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	// Use colorful logging for server startup
	s.prettyLog.ServerStarting(addr, s.config.OIDCLD.Issuer, true)

	// If autocert manager is configured, prefer it when no cert/key provided.
	if s.autocertManager != nil {
		// If both autocert and explicit cert/key are provided, that's ambiguous — error out.
		if certFile != "" || keyFile != "" {
			return fmt.Errorf("autocert is configured AND TLS certificate/key were provided; choose one (remove autocert settings or provide no cert/key)")
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

	// No autocert manager configured: require certFile and keyFile.
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("no autocert configured and TLS certificate/key not provided")
	}

	return server.ListenAndServeTLS(certFile, keyFile)
}

// UpdateConfig updates the server configuration at runtime
func (s *Server) UpdateConfig(newConfig *config.Config) error {
	// Validate the new configuration
	if newConfig == nil {
		return ErrConfigurationCannotBeNil
	}

	// Validate issuer hasn't changed (would require server restart)
	if s.config.OIDCLD.Issuer != newConfig.OIDCLD.Issuer {
		return fmt.Errorf("%w: old=%s, new=%s",
			ErrIssuerURLCannotBeChanged, s.config.OIDCLD.Issuer, newConfig.OIDCLD.Issuer)
	}

	// Validate algorithm hasn't changed (would require new keys)
	oldAlgorithm := s.config.OIDCLD.Algorithm
	if oldAlgorithm == "" {
		oldAlgorithm = "RS256" // Default
	}
	newAlgorithm := newConfig.OIDCLD.Algorithm
	if newAlgorithm == "" {
		newAlgorithm = "RS256" // Default
	}
	if oldAlgorithm != newAlgorithm {
		return fmt.Errorf("%w: old=%s, new=%s",
			ErrSigningAlgorithmCannotBeChanged, oldAlgorithm, newAlgorithm)
	}

	// Track changes for colorful logging
	var changes []string

	// Check for user changes
	if len(s.config.Users) != len(newConfig.Users) {
		changes = append(changes, fmt.Sprintf("Users: %d → %d", len(s.config.Users), len(newConfig.Users)))
	}

	// Check for scope changes
	if len(s.config.OIDCLD.ValidScopes) != len(newConfig.OIDCLD.ValidScopes) {
		changes = append(changes, fmt.Sprintf("Valid Scopes: %d → %d", len(s.config.OIDCLD.ValidScopes), len(newConfig.OIDCLD.ValidScopes)))
	}

	// Check for audience changes
	if len(s.config.OIDCLD.ValidAudiences) != len(newConfig.OIDCLD.ValidAudiences) {
		changes = append(changes, fmt.Sprintf("Valid Audiences: %d → %d", len(s.config.OIDCLD.ValidAudiences), len(newConfig.OIDCLD.ValidAudiences)))
	}

	// Check token expiration changes
	if s.config.OIDCLD.ExpiredIn != newConfig.OIDCLD.ExpiredIn {
		changes = append(changes, fmt.Sprintf("Token Expiry: %ds → %ds", s.config.OIDCLD.ExpiredIn, newConfig.OIDCLD.ExpiredIn))
	}

	// Check refresh token settings
	if s.config.OIDCLD.RefreshTokenEnabled != newConfig.OIDCLD.RefreshTokenEnabled {
		changes = append(changes, fmt.Sprintf("Refresh Tokens: %v → %v", s.config.OIDCLD.RefreshTokenEnabled, newConfig.OIDCLD.RefreshTokenEnabled))
	}

	// Update the configuration atomically
	s.config = newConfig

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

		// If this is the health endpoint and verbose logging is not enabled,
		// skip emitting the access log entirely.
		if r.URL != nil && r.URL.Path == "/health" {
			if s == nil || s.config == nil || !s.config.OIDCLD.VerboseLogging {
				return
			}
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
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleDiscovery provides a custom discovery endpoint with pretty-printed JSON
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	// Get the discovery configuration from the provider
	issuer := s.provider.IssuerFromRequest(r)

	// Create the discovery document
	discovery := map[string]interface{}{
		"issuer":                                                   issuer,
		"authorization_endpoint":                                   issuer + "/authorize",
		"token_endpoint":                                           issuer + "/token",
		"introspection_endpoint":                                   issuer + "/oauth/introspect",
		"userinfo_endpoint":                                        issuer + "/userinfo",
		"revocation_endpoint":                                      issuer + "/revoke",
		"end_session_endpoint":                                     issuer + "/end_session",
		"device_authorization_endpoint":                            issuer + "/device_authorization",
		"jwks_uri":                                                 issuer + "/keys",
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
	if s.config.OIDCLD.EndSessionEnabled && s.config.OIDCLD.EndSessionEndpointVisible {
		// end_session_endpoint is already included above
	} else if !s.config.OIDCLD.EndSessionEnabled {
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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set key ID header
	token.Header["kid"] = "oidcld-key"

	return token.SignedString(s.privateKey)
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
	expiry := now.Add(time.Duration(s.config.OIDCLD.ExpiredIn) * time.Second)

	// Generate access token
	accessTokenClaims := jwt.MapClaims{
		"iss":       s.config.OIDCLD.Issuer,
		"sub":       userID,
		"aud":       clientID,
		"exp":       expiry.Unix(),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"scope":     strings.Join(scopes, " "),
		"client_id": clientID,
	}

	// Add custom claims from user config
	for key, value := range user.ExtraClaims {
		accessTokenClaims[key] = value
	}

	accessToken, err = s.signJWT(accessTokenClaims)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate ID token (only if openid scope is requested)
	if slices.Contains(scopes, "openid") {
		idTokenClaims := jwt.MapClaims{
			"iss": s.config.OIDCLD.Issuer,
			"sub": userID,
			"aud": clientID,
			"exp": expiry.Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		}

		// Add profile claims if profile scope is requested
		if slices.Contains(scopes, "profile") {
			idTokenClaims["name"] = user.DisplayName
			if givenName, ok := user.ExtraClaims["given_name"]; ok {
				idTokenClaims["given_name"] = givenName
			}
			if familyName, ok := user.ExtraClaims["family_name"]; ok {
				idTokenClaims["family_name"] = familyName
			}
		}

		// Add email claims if email scope is requested
		if slices.Contains(scopes, "email") {
			if email, ok := user.ExtraClaims["email"]; ok {
				idTokenClaims["email"] = email
				idTokenClaims["email_verified"] = true
			}
		}

		// Add other custom claims
		for key, value := range user.ExtraClaims {
			if key != "given_name" && key != "family_name" && key != "email" {
				idTokenClaims[key] = value
			}
		}

		idToken, err = s.signJWT(idTokenClaims)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	// Generate refresh token if enabled
	if s.config.OIDCLD.RefreshTokenEnabled {
		refreshTokenClaims := jwt.MapClaims{
			"iss":       s.config.OIDCLD.Issuer,
			"sub":       userID,
			"aud":       clientID,
			"exp":       now.Add(time.Duration(s.config.OIDCLD.RefreshTokenExpiry) * time.Second).Unix(),
			"iat":       now.Unix(),
			"nbf":       now.Unix(),
			"token_use": "refresh",
			"scope":     strings.Join(scopes, " "),
		}

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

	// Check if client is valid
	if !slices.Contains(s.config.OIDCLD.ValidAudiences, clientID) {
		s.writeTokenError(w, "invalid_client", "invalid client_id")
		return
	}

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
	tokenResponse := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   s.config.OIDCLD.ExpiredIn,
		"id_token":     idToken,
		"scope":        strings.Join(deviceAuth.Scopes, " "),
	}

	// Add refresh token if enabled
	if s.config.OIDCLD.RefreshTokenEnabled && refreshToken != "" {
		tokenResponse["refresh_token"] = refreshToken
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
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

	grantType := r.FormValue("grant_type")

	// Handle device flow token requests manually
	if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
		s.handleDeviceFlowTokenRequest(w, r)
		return
	}

	// For all other grant types, use zitadel/oidc default logic
	s.provider.ServeHTTP(w, r)
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
	html := fmt.Sprintf(`
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
			html += fmt.Sprintf(`
            <li>
                <form method="POST" action="%s" style="display: inline-block; width: 100%%;">`, config.FormAction)

			// Add hidden fields
			for name, value := range config.HiddenFields {
				html += fmt.Sprintf(`
                    <input type="hidden" name="%s" value="%s">`, name, value)
			}

			html += fmt.Sprintf(`
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

			html += fmt.Sprintf(`
            <li>
                <button type="button" onclick="%s(%s)" class="user-button" aria-label="%s">
                    <span class="user-name">%s</span>
                    <span class="user-email">%s</span>
                </button>
            </li>`, config.ButtonAction, actionParams, userID, user.DisplayName, email)
		}
	}

	html += fmt.Sprintf(`
        </ul>
        %s
    </div>
    %s
</body>
</html>`, config.ExtraHTML, config.ExtraScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
