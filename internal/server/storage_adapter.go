package server

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Static errors for OIDC storage adapter
var (
	ErrAuthRequestNotFound  = errors.New("auth request not found")
	ErrCodeNotFound         = errors.New("code not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrTokenNotFound        = errors.New("token not found")
	ErrClientKeyNotFound    = errors.New("client key not found")
	ErrDeviceAuthNotFound   = errors.New("device authorization not found")
	ErrDeviceAuthExpired    = errors.New("device authorization expired")
	ErrUserCodeNotFound     = errors.New("user code not found")
)

// StorageAdapter adapts our MemoryStorage to zitadel/oidc storage interface
type StorageAdapter struct {
	lock          sync.Mutex
	config        *config.Config
	privateKey    *rsa.PrivateKey
	authRequests  map[string]*AuthRequest
	codes         map[string]string
	tokens        map[string]*Token
	refreshTokens map[string]*RefreshToken
	signingKey    SigningKey
	userSessions  map[string]*UserSession // New: user session tracking
	tokenIndex    map[string]string       // New: token -> user mapping

	// Device flow storage
	deviceAuthorizations map[string]*DeviceAuthorization // deviceCode -> DeviceAuthorization
	userCodeToDevice     map[string]string               // userCode -> deviceCode

	// Logger for colorful output
	prettyLog *Logger
}

// NewStorageAdapter creates a new storage adapter
func NewStorageAdapter(config *config.Config, privateKey *rsa.PrivateKey) *StorageAdapter {
	return &StorageAdapter{
		config:               config,
		privateKey:           privateKey,
		authRequests:         make(map[string]*AuthRequest),
		codes:                make(map[string]string),
		tokens:               make(map[string]*Token),
		refreshTokens:        make(map[string]*RefreshToken),
		userSessions:         make(map[string]*UserSession),         // New: initialize session tracking
		tokenIndex:           make(map[string]string),               // New: initialize token index
		deviceAuthorizations: make(map[string]*DeviceAuthorization), // Device flow storage
		userCodeToDevice:     make(map[string]string),               // User code mapping
		prettyLog:            NewLogger(),                           // Initialize colorful logger
		signingKey: SigningKey{
			id:        uuid.NewString(),
			algorithm: jose.RS256,
			key:       privateKey,
		},
	}
}

// ClientCredentials implements op.ClientCredentialsStorage interface
func (s *StorageAdapter) ClientCredentials(_ context.Context, clientID, clientSecret string) (op.Client, error) {
	// Validate credentials are non-empty (accept any non-empty credentials like legacy)
	if err := ValidateClientCredentials(clientID, clientSecret); err != nil {
		return nil, fmt.Errorf("client credentials validation failed: %w", err)
	}

	// Create client with client credentials grant type
	client := NewClientCredentialsClient(clientID, clientSecret, s.config)

	return client, nil
}

// ClientCredentialsTokenRequest implements op.ClientCredentialsStorage interface
func (s *StorageAdapter) ClientCredentialsTokenRequest(_ context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	// Create token request with client as subject
	tokenReq := NewClientCredentialsTokenRequest(
		clientID,
		scopes,
		[]string{},
	)

	return tokenReq, nil
}

// CreateAuthRequest implements op.Storage interface
func (s *StorageAdapter) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Handle prompt=none case
	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		return nil, oidc.ErrLoginRequired()
	}

	// Create internal auth request
	request := &AuthRequest{
		ID:           uuid.NewString(),
		ClientID:     authReq.ClientID,
		UserID:       userID,
		RedirectURI:  authReq.RedirectURI,
		Scopes:       authReq.Scopes,
		ResponseType: authReq.ResponseType,
		ResponseMode: authReq.ResponseMode, // Capture response mode from request
		State:        authReq.State,
		Nonce:        authReq.Nonce,
		CodeChallenge: &oidc.CodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    authReq.CodeChallengeMethod,
		},
		AuthTime: time.Now(),
		done:     false,
	}

	// Store the auth request
	s.authRequests[request.ID] = request

	return request, nil
}

// AuthRequestByID implements op.Storage interface
func (s *StorageAdapter) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	request, ok := s.authRequests[id]
	if !ok {
		return nil, ErrAuthRequestNotFound
	}

	return request, nil
}

// AuthRequestByCode implements op.Storage interface
func (s *StorageAdapter) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	authReqID, ok := s.codes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}

	request, ok := s.authRequests[authReqID]
	if !ok {
		return nil, ErrAuthRequestNotFound
	}

	// Delete the code after use
	delete(s.codes, code)

	return request, nil
}

// SaveAuthCode implements op.Storage interface
func (s *StorageAdapter) SaveAuthCode(ctx context.Context, id, code string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if auth request exists
	if _, ok := s.authRequests[id]; !ok {
		return ErrAuthRequestNotFound
	}

	// Store the code mapping
	s.codes[code] = id

	return nil
}

// CompleteAuthRequest marks an auth request as completed with the given user
func (s *StorageAdapter) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	authReq, exists := s.authRequests[authRequestID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrAuthRequestNotFound, authRequestID)
	}

	// Set the user ID and mark as done
	authReq.UserID = userID
	authReq.done = true
	authReq.AuthTime = time.Now()

	s.authRequests[authRequestID] = authReq
	return nil
}

// DeleteAuthRequest implements op.Storage interface
func (s *StorageAdapter) DeleteAuthRequest(ctx context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.authRequests, id)
	return nil
}

// CreateAccessToken implements op.Storage interface
func (s *StorageAdapter) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	tokenID := uuid.NewString()
	expiration := time.Now().Add(time.Duration(s.config.OIDCLD.ExpiredIn) * time.Second)

	token := &Token{
		ID:        tokenID,
		Subject:   request.GetSubject(),
		Audience:  request.GetAudience(),
		Scopes:    request.GetScopes(),
		ExpiresAt: expiration,
	}

	s.tokens[tokenID] = token

	// Log token issuance with colorful output
	clientID := ""
	if len(request.GetAudience()) > 0 {
		clientID = request.GetAudience()[0]
	}
	s.prettyLog.TokenIssued(clientID, request.GetSubject(), "access_token", request.GetScopes())

	return tokenID, expiration, nil
}

// CreateAccessAndRefreshTokens implements op.Storage interface
func (s *StorageAdapter) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Create access token
	accessTokenID := uuid.NewString()
	expiration := time.Now().Add(time.Duration(s.config.OIDCLD.ExpiredIn) * time.Second)

	accessToken := &Token{
		ID:        accessTokenID,
		Subject:   request.GetSubject(),
		Audience:  request.GetAudience(),
		Scopes:    request.GetScopes(),
		ExpiresAt: expiration,
	}

	s.tokens[accessTokenID] = accessToken

	// Create refresh token if enabled
	var refreshTokenID string
	if s.config.OIDCLD.RefreshTokenEnabled {
		refreshTokenID = uuid.NewString()
		refreshExpiration := time.Now().Add(time.Duration(s.config.OIDCLD.RefreshTokenExpiry) * time.Second)

		refreshToken := &RefreshToken{
			ID:        refreshTokenID,
			Subject:   request.GetSubject(),
			Audience:  request.GetAudience(),
			Scopes:    request.GetScopes(),
			ExpiresAt: refreshExpiration,
			AuthTime:  time.Now(),
		}

		s.refreshTokens[refreshTokenID] = refreshToken

		// Delete old refresh token if provided
		if currentRefreshToken != "" {
			delete(s.refreshTokens, currentRefreshToken)
		}
	}

	return accessTokenID, refreshTokenID, expiration, nil
}

// TokenRequestByRefreshToken implements op.Storage interface
func (s *StorageAdapter) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	refreshToken, ok := s.refreshTokens[refreshTokenID]
	if !ok {
		return nil, ErrRefreshTokenNotFound
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		delete(s.refreshTokens, refreshTokenID)
		return nil, ErrRefreshTokenExpired
	}

	return refreshToken, nil
}

// TerminateSession implements op.Storage interface
func (s *StorageAdapter) TerminateSession(ctx context.Context, userID string, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Remove all tokens for this user/client combination
	for tokenID, token := range s.tokens {
		if token.Subject == userID && len(token.Audience) > 0 && token.Audience[0] == clientID {
			delete(s.tokens, tokenID)
		}
	}

	for refreshID, refresh := range s.refreshTokens {
		if refresh.Subject == userID && refresh.GetClientID() == clientID {
			delete(s.refreshTokens, refreshID)
		}
	}

	return nil
}

// RevokeToken implements op.Storage interface
func (s *StorageAdapter) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Try to revoke as access token
	if token, ok := s.tokens[tokenOrTokenID]; ok {
		if token.Subject == userID && len(token.Audience) > 0 && token.Audience[0] == clientID {
			delete(s.tokens, tokenOrTokenID)
			return nil
		}
	}

	// Try to revoke as refresh token
	if refresh, ok := s.refreshTokens[tokenOrTokenID]; ok {
		if refresh.Subject == userID && refresh.GetClientID() == clientID {
			delete(s.refreshTokens, tokenOrTokenID)
			return nil
		}
	}

	return oidc.ErrInvalidRequest().WithDescription("token not found")
}

// GetRefreshTokenInfo implements op.Storage interface
func (s *StorageAdapter) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (string, string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	refreshToken, ok := s.refreshTokens[token]
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}

	if refreshToken.GetClientID() != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}

	return refreshToken.Subject, token, nil
}

// SigningKey implements op.Storage interface
func (s *StorageAdapter) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return &s.signingKey, nil
}

// SignatureAlgorithms implements op.Storage interface
func (s *StorageAdapter) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet implements op.Storage interface
func (s *StorageAdapter) KeySet(ctx context.Context) ([]op.Key, error) {
	publicKey := &s.privateKey.PublicKey

	key := &Key{
		id:        s.signingKey.id,
		algorithm: jose.RS256,
		use:       "sig",
		publicKey: publicKey,
	}

	return []op.Key{key}, nil
}

// SetUserinfoFromScopes implements op.Storage interface
func (s *StorageAdapter) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID string, clientID string, scopes []string) error {
	// Get user from config
	user, exists := s.config.Users[userID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	// Set basic user info
	userinfo.Subject = userID

	// Add claims based on scopes
	for _, scope := range scopes {
		switch scope {
		case "profile":
			userinfo.Name = user.DisplayName
			userinfo.PreferredUsername = userID
		case "email":
			if email, ok := user.ExtraClaims["email"].(string); ok {
				userinfo.Email = email
				userinfo.EmailVerified = oidc.Bool(true)
			}
		}
	}

	// Add custom claims
	if userinfo.Claims == nil {
		userinfo.Claims = make(map[string]any)
	}

	for key, value := range user.ExtraClaims {
		// Skip standard claims that are already handled
		if key != "email" && key != "name" {
			userinfo.Claims[key] = value
		}
	}

	return nil
}

// SetUserinfoFromToken implements op.Storage interface
func (s *StorageAdapter) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, _ string, _ string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Find the token
	token, exists := s.tokens[tokenID]
	if !exists {
		return ErrTokenNotFound
	}

	// Use the same logic as SetUserinfoFromScopes
	return s.SetUserinfoFromScopes(ctx, userinfo, token.Subject, token.Audience[0], token.Scopes)
}

// SetIntrospectionFromToken implements op.Storage interface
func (s *StorageAdapter) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID string, subject string, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Find the token
	token, exists := s.tokens[tokenID]
	if !exists {
		introspection.Active = false
		return nil
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		introspection.Active = false
		return nil
	}

	// Set introspection response
	introspection.Active = true
	introspection.ClientID = clientID
	introspection.Subject = token.Subject
	introspection.Audience = oidc.Audience(token.Audience)
	introspection.Scope = oidc.SpaceDelimitedArray(token.Scopes)
	introspection.Expiration = oidc.FromTime(token.ExpiresAt)

	return nil
}

// GetPrivateClaimsFromScopes implements op.Storage interface
func (s *StorageAdapter) GetPrivateClaimsFromScopes(ctx context.Context, userID string, clientID string, scopes []string) (map[string]any, error) {
	// Get user from config
	user, exists := s.config.Users[userID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	claims := make(map[string]any)

	// Add custom claims based on scopes
	for _, scope := range scopes {
		// Check if user has this scope
		if slices.Contains(user.ExtraValidScopes, scope) {
			// Add all extra claims for this user
			// In a real implementation, you might want to filter claims by scope
			for key, value := range user.ExtraClaims {
				claims[key] = value
			}
		}
	}

	return claims, nil
}

// GetKeyByIDAndClientID implements op.Storage interface
func (s *StorageAdapter) GetKeyByIDAndClientID(ctx context.Context, keyID string, clientID string) (*jose.JSONWebKey, error) {
	// For client authentication with private_key_jwt
	// This would typically return client-specific keys
	// For now, return nil to indicate no client-specific keys
	return nil, ErrClientKeyNotFound
}

// ValidateJWTProfileScopes implements op.Storage interface
func (s *StorageAdapter) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	// Get user from config
	user, exists := s.config.Users[userID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	// Validate scopes against user's allowed scopes
	validScopes := []string{}
	standardScopes := map[string]bool{
		"openid":  true,
		"profile": true,
		"email":   true,
	}

	for _, scope := range scopes {
		if standardScopes[scope] {
			validScopes = append(validScopes, scope)
			continue
		}

		// Check custom scopes
		if slices.Contains(user.ExtraValidScopes, scope) {
			validScopes = append(validScopes, scope)
		}
	}

	return validScopes, nil
}

// Health implements op.Storage interface
func (s *StorageAdapter) Health(ctx context.Context) error {
	return nil
}

// GetClientByClientID implements op.OPStorage interface (renamed from GetClientByID)
func (s *StorageAdapter) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	// For testing purposes, accept any client ID and return a permissive client
	// Return nil error so this satisfies the op.Storage interface while remaining permissive for tests
	client := &Client{
		id: clientID,
		// For test identity provider, we allow any redirect URI for development flexibility
		// This makes it easier to test with different frameworks and ports
		redirectURIs:    []string{"*"}, // Special wildcard to accept any redirect URI
		applicationType: op.ApplicationTypeWeb,
		authMethod:      oidc.AuthMethodNone, // Public client
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes: []oidc.GrantType{
			oidc.GrantTypeCode,
			oidc.GrantTypeClientCredentials,
			oidc.GrantTypeRefreshToken,
			oidc.GrantTypeDeviceCode,
		},
		loginURL: func(id string) string {
			return "/login?authRequestID=" + id
		},
		accessTokenType:                op.AccessTokenTypeJWT,
		devMode:                        true, // Allow non-compliant configs for testing
		idTokenUserinfoClaimsAssertion: true,
		clockSkew:                      time.Minute,
		scopes:                         s.buildScopes(),
	}
	return client, nil
}

// AuthorizeClientIDSecret implements op.OPStorage interface
func (s *StorageAdapter) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	// For testing purposes, always allow the client (do not perform existence/secret checks)
	return nil
}

// buildScopes builds the complete list of supported scopes
func (s *StorageAdapter) buildScopes() []string {
	scopes := []string{"openid", "profile", "email"}
	scopes = append(scopes, s.config.OIDCLD.ValidScopes...)
	return scopes
}

// AuthRequest implements op.AuthRequest interface
type AuthRequest struct {
	ID            string
	ClientID      string
	UserID        string
	RedirectURI   string
	Scopes        []string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode // Store the response mode from the request
	State         string
	Nonce         string
	CodeChallenge *oidc.CodeChallenge
	AuthTime      time.Time
	done          bool
}

// GetID returns the authorization request ID
func (r *AuthRequest) GetID() string { return r.ID }

// GetACR returns the Authentication Context Class Reference
func (r *AuthRequest) GetACR() string { return "" }

// GetAMR returns the Authentication Methods References
func (r *AuthRequest) GetAMR() []string { return []string{} }

// GetAudience returns the intended audience for this request
func (r *AuthRequest) GetAudience() []string { return []string{r.ClientID} }

// GetAuthTime returns the time when authentication occurred
func (r *AuthRequest) GetAuthTime() time.Time { return r.AuthTime }

// GetClientID returns the client identifier
func (r *AuthRequest) GetClientID() string { return r.ClientID }

// GetCodeChallenge returns the PKCE code challenge
func (r *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge { return r.CodeChallenge }

// GetNonce returns the nonce value
func (r *AuthRequest) GetNonce() string { return r.Nonce }

// GetRedirectURI returns the redirect URI
func (r *AuthRequest) GetRedirectURI() string { return r.RedirectURI }

// GetResponseType returns the OAuth response type
func (r *AuthRequest) GetResponseType() oidc.ResponseType { return r.ResponseType }

// GetResponseMode returns the OAuth response mode
func (r *AuthRequest) GetResponseMode() oidc.ResponseMode { return r.ResponseMode }

// GetScopes returns the requested scopes
func (r *AuthRequest) GetScopes() []string { return r.Scopes }

// GetState returns the state parameter
func (r *AuthRequest) GetState() string { return r.State }

// GetSubject returns the subject (user ID)
func (r *AuthRequest) GetSubject() string { return r.UserID }

// Done returns whether the request is completed
func (r *AuthRequest) Done() bool { return r.done }

// Token represents an access token
type Token struct {
	ID        string
	Subject   string
	Audience  []string
	Scopes    []string
	ExpiresAt time.Time
}

// RefreshToken represents a refresh token and implements op.RefreshTokenRequest
type RefreshToken struct {
	ID            string
	Subject       string
	Audience      []string
	Scopes        []string
	ExpiresAt     time.Time
	AuthTime      time.Time
	currentScopes []string
}

// GetAMR returns the refresh token ID
func (r *RefreshToken) GetAMR() []string { return []string{} }

// GetAudience returns the Authentication Context Class Reference
func (r *RefreshToken) GetAudience() []string { return r.Audience }

// GetAuthTime returns the time when authentication occurred
func (r *RefreshToken) GetAuthTime() time.Time { return r.AuthTime }

// GetClientID returns the client identifier
func (r *RefreshToken) GetClientID() string {
	if len(r.Audience) > 0 {
		return r.Audience[0]
	}
	return ""
}

// GetScopes returns the requested scopes
func (r *RefreshToken) GetScopes() []string {
	if r.currentScopes != nil {
		return r.currentScopes
	}
	return r.Scopes
}

// GetSubject returns the subject (user ID)
func (r *RefreshToken) GetSubject() string { return r.Subject }

// SetCurrentScopes sets the current scopes for the refresh token
func (r *RefreshToken) SetCurrentScopes(scopes []string) { r.currentScopes = scopes }

// SigningKey implements op.SigningKey interface
type SigningKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

// SignatureAlgorithm implements op.SigningKey interface
func (k *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.algorithm }

// Key implements op.SigningKey interface
func (k *SigningKey) Key() any { return k.key }

// ID implements op.SigningKey interface
func (k *SigningKey) ID() string { return k.id }

// Key implements op.Key interface
type Key struct {
	id        string
	algorithm jose.SignatureAlgorithm
	use       string
	publicKey *rsa.PublicKey
}

// Algorithm implements op.Key interface
func (k *Key) Algorithm() jose.SignatureAlgorithm { return k.algorithm }

// Use implements op.Key interface
func (k *Key) Use() string { return k.use }

// Key implements op.Key interface
func (k *Key) Key() any { return k.publicKey }

// ID implements op.Key interface
func (k *Key) ID() string { return k.id }

// Client implements op.Client interface
type Client struct {
	id                             string
	redirectURIs                   []string
	applicationType                op.ApplicationType
	authMethod                     oidc.AuthMethod
	responseTypes                  []oidc.ResponseType
	grantTypes                     []oidc.GrantType
	loginURL                       func(string) string
	accessTokenType                op.AccessTokenType
	devMode                        bool
	idTokenUserinfoClaimsAssertion bool
	clockSkew                      time.Duration
	scopes                         []string
}

// GetID returns the client ID
func (c *Client) GetID() string { return c.id }

// RedirectURIs returns the redirect URIs for the client
// For test identity provider, we're flexible with redirect URIs to support development
func (c *Client) RedirectURIs() []string {
	// If we have a wildcard, return a comprehensive list of common development URIs
	if len(c.redirectURIs) == 1 && c.redirectURIs[0] == "*" {
		return []string{
			// Common development ports for various frameworks
			"http://localhost:3000/callback",  // React (Create React App)
			"http://localhost:5173/callback",  // Vite (Vue, React, etc.)
			"http://localhost:4173/callback",  // Vite preview
			"http://localhost:8080/callback",  // Webpack dev server
			"http://localhost:4200/callback",  // Angular CLI
			"http://localhost:3001/callback",  // Alternative React port
			"http://localhost:8000/callback",  // Django/Python
			"http://localhost:9000/callback",  // Alternative port
			"http://localhost:18888/callback", // Self-testing
			// HTTPS versions
			"https://localhost:3000/callback",
			"https://localhost:5173/callback",
			"https://localhost:4173/callback",
			"https://localhost:8080/callback",
			"https://localhost:4200/callback",
			// Common callback paths
			"http://localhost:3000/auth/callback",
			"http://localhost:5173/auth/callback",
			"http://localhost:8080/auth/callback",
			// Root paths for logout
			"http://localhost:3000",
			"http://localhost:5173",
			"http://localhost:8080",
			"http://localhost:4200",
			"https://localhost:3000",
			"https://localhost:5173",
			"https://localhost:8080",
			"https://localhost:4200",
			// Example domains for testing
			"https://app.example.com/auth/callback",
			"https://legacy.example.com/callback",
		}
	}
	return c.redirectURIs
}

// PostLogoutRedirectURIs returns the post logout redirect URIs
// For test identity provider, we're flexible to support development
func (c *Client) PostLogoutRedirectURIs() []string {
	// Return common development logout URIs
	return []string{
		"http://localhost:3000",
		"http://localhost:5173",
		"http://localhost:4173",
		"http://localhost:8080",
		"http://localhost:4200",
		"https://localhost:3000",
		"https://localhost:5173",
		"https://localhost:8080",
		"https://localhost:4200",
		"https://app.example.com",
		"https://legacy.example.com",
	}
}

// ApplicationType returns the application type of the client
func (c *Client) ApplicationType() op.ApplicationType { return c.applicationType }

// AuthMethod returns the authentication method for the client
func (c *Client) AuthMethod() oidc.AuthMethod { return c.authMethod }

// ResponseTypes returns the supported response types for the client
func (c *Client) ResponseTypes() []oidc.ResponseType { return c.responseTypes }

// GrantTypes returns the supported grant types for the client
func (c *Client) GrantTypes() []oidc.GrantType { return c.grantTypes }

// LoginURL returns the login URL for the client
func (c *Client) LoginURL(id string) string { return c.loginURL(id) }

// AccessTokenType returns the type of access token used by the client
func (c *Client) AccessTokenType() op.AccessTokenType { return c.accessTokenType }

// IDTokenLifetime returns the lifetime of ID tokens issued to this client
func (c *Client) IDTokenLifetime() time.Duration { return time.Hour }

// DevMode returns whether the client is in development mode
func (c *Client) DevMode() bool { return c.devMode }

// RestrictAdditionalIdTokenScopes restricts additional scopes for ID and access tokens
func (c *Client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// RestrictAdditionalAccessTokenScopes restricts additional scopes for access tokens
func (c *Client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// IsScopeAllowed checks if the given scope is allowed for this client
func (c *Client) IsScopeAllowed(scope string) bool {
	return slices.Contains(c.scopes, scope)
}

// IDTokenUserinfoClaimsAssertion returns whether ID token userinfo claims assertion is enabled
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return c.idTokenUserinfoClaimsAssertion }

// ClockSkew returns the clock skew duration for this client
func (c *Client) ClockSkew() time.Duration { return c.clockSkew }

// UpdateConfig updates the storage adapter configuration at runtime
func (s *StorageAdapter) UpdateConfig(newConfig *config.Config) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Update the configuration
	s.config = newConfig
}

// DeviceAuthorization represents a device authorization request
type DeviceAuthorization struct {
	ClientID   string
	DeviceCode string
	UserCode   string
	Scopes     []string
	Expires    time.Time

	// State fields
	Done     bool
	Denied   bool
	Subject  string
	AuthTime time.Time
}

// StoreDeviceAuthorization implements op.DeviceAuthorizationStorage interface
func (s *StorageAdapter) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if user code already exists
	if _, exists := s.userCodeToDevice[userCode]; exists {
		return op.ErrDuplicateUserCode
	}

	// Store the device authorization
	deviceAuth := &DeviceAuthorization{
		ClientID:   clientID,
		DeviceCode: deviceCode,
		UserCode:   userCode,
		Scopes:     scopes,
		Expires:    expires,
		Done:       false,
		Denied:     false,
	}

	s.deviceAuthorizations[deviceCode] = deviceAuth
	s.userCodeToDevice[userCode] = deviceCode

	// Log device flow start with colorful output
	s.prettyLog.DeviceFlowStarted(clientID, userCode, deviceCode)

	return nil
}

// GetDeviceAuthorizatonState implements op.DeviceAuthorizationStorage interface
func (s *StorageAdapter) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	deviceAuth, exists := s.deviceAuthorizations[deviceCode]
	if !exists {
		return nil, ErrDeviceAuthNotFound
	}

	// Check if it belongs to the correct client
	if deviceAuth.ClientID != clientID {
		return nil, fmt.Errorf("%w for client", ErrDeviceAuthNotFound)
	}

	// Check if expired
	if time.Now().After(deviceAuth.Expires) {
		// Clean up expired authorization
		delete(s.deviceAuthorizations, deviceCode)
		delete(s.userCodeToDevice, deviceAuth.UserCode)
		return nil, ErrDeviceAuthExpired
	}

	// Return the current state
	state := &op.DeviceAuthorizationState{
		ClientID: deviceAuth.ClientID,
		Audience: []string{deviceAuth.ClientID},
		Scopes:   deviceAuth.Scopes,
		Expires:  deviceAuth.Expires,
		Done:     deviceAuth.Done,
		Denied:   deviceAuth.Denied,
		Subject:  deviceAuth.Subject,
		AuthTime: deviceAuth.AuthTime,
	}

	return state, nil
}

// CompleteDeviceAuthorization completes a device authorization (called from device UI)
func (s *StorageAdapter) CompleteDeviceAuthorization(userCode, userID string, approved bool) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	deviceCode, exists := s.userCodeToDevice[userCode]
	if !exists {
		return ErrUserCodeNotFound
	}

	deviceAuth, exists := s.deviceAuthorizations[deviceCode]
	if !exists {
		return ErrDeviceAuthNotFound
	}

	// Check if expired
	if time.Now().After(deviceAuth.Expires) {
		// Clean up expired authorization
		delete(s.deviceAuthorizations, deviceCode)
		delete(s.userCodeToDevice, userCode)
		return ErrDeviceAuthExpired
	}

	// Update the authorization state
	if approved {
		deviceAuth.Done = true
		deviceAuth.Subject = userID
		deviceAuth.AuthTime = time.Now()
	} else {
		deviceAuth.Denied = true
	}

	// Log device flow completion with colorful output
	s.prettyLog.DeviceFlowCompleted(userCode, userID, approved)

	return nil
}
