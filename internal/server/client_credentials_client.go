package server

import (
	"errors"
	"slices"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Static errors for client credentials.
var (
	ErrMissingClientCredentials = errors.New("missing client credentials")
)

// ClientCredentialsClient implements op.Client interface specifically for client credentials flow.
type ClientCredentialsClient struct {
	id          string
	validScopes []string
}

// NewClientCredentialsClient creates a new OIDC client configured for client credentials flow.
func NewClientCredentialsClient(clientID, _ string, config *config.Config) *ClientCredentialsClient {
	return &ClientCredentialsClient{
		id:          clientID,
		validScopes: config.OIDCLD.ValidScopes,
	}
}

// GetID returns the client ID.
func (c *ClientCredentialsClient) GetID() string {
	return c.id
}

// RedirectURIs returns redirect URIs (not used for client credentials)
func (c *ClientCredentialsClient) RedirectURIs() []string {
	return []string{}
}

// PostLogoutRedirectURIs returns post-logout redirect URIs (not used for client credentials)
func (c *ClientCredentialsClient) PostLogoutRedirectURIs() []string {
	return []string{}
}

// ApplicationType returns the application type
func (c *ClientCredentialsClient) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeWeb
}

// AuthMethod returns the authentication method
func (c *ClientCredentialsClient) AuthMethod() oidc.AuthMethod {
	return oidc.AuthMethodBasic
}

// ResponseTypes returns supported response types (not used for client credentials)
func (c *ClientCredentialsClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{}
}

// GrantTypes returns supported grant types
func (c *ClientCredentialsClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeClientCredentials}
}

// LoginURL returns the login URL (not used for client credentials)
func (c *ClientCredentialsClient) LoginURL(string) string {
	return ""
}

// AccessTokenType returns the access token type
func (c *ClientCredentialsClient) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}

// IDTokenLifetime returns the ID token lifetime (not used for client credentials)
func (c *ClientCredentialsClient) IDTokenLifetime() time.Duration {
	return time.Hour
}

// DevMode returns whether the client is in development mode
func (c *ClientCredentialsClient) DevMode() bool {
	return false
}

// RestrictAdditionalIdTokenScopes restricts additional ID token scopes (not used for client credentials)
func (c *ClientCredentialsClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(_ []string) []string {
		return []string{}
	}
}

// RestrictAdditionalAccessTokenScopes restricts additional access token scopes
func (c *ClientCredentialsClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		// If no valid scopes configured, reject all scopes
		if len(c.validScopes) == 0 {
			return nil
		}

		// Filter scopes to only include allowed ones
		var allowedScopes []string
		for _, scope := range scopes {
			if slices.Contains(c.validScopes, scope) {
				allowedScopes = append(allowedScopes, scope)
			}
		}

		// Return nil if no scopes were allowed to match expected behavior
		if len(allowedScopes) == 0 {
			return nil
		}

		return allowedScopes
	}
}

// IsScopeAllowed checks if a scope is allowed for this client
func (c *ClientCredentialsClient) IsScopeAllowed(scope string) bool {
	// If no valid scopes configured, reject all scopes
	if len(c.validScopes) == 0 {
		return false
	}

	// Check if scope is in valid scopes list
	return slices.Contains(c.validScopes, scope)
}

// IDTokenUserinfoClaimsAssertion returns whether ID token userinfo claims assertion is enabled
func (c *ClientCredentialsClient) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

// ClockSkew returns the allowed clock skew
func (c *ClientCredentialsClient) ClockSkew() time.Duration {
	return 5 * time.Minute
}

// ClientCredentialsTokenRequest implements op.TokenRequest interface for client credentials
type ClientCredentialsTokenRequest struct {
	clientID string
	scopes   []string
	audience []string
}

// NewClientCredentialsTokenRequest creates a new client credentials token request
func NewClientCredentialsTokenRequest(clientID string, scopes []string, audience []string) *ClientCredentialsTokenRequest {
	return &ClientCredentialsTokenRequest{
		clientID: clientID,
		scopes:   scopes,
		audience: audience,
	}
}

// GetSubject returns the subject (client ID for client credentials)
func (r *ClientCredentialsTokenRequest) GetSubject() string {
	return r.clientID
}

// GetAudience returns the audience
func (r *ClientCredentialsTokenRequest) GetAudience() []string {
	return r.audience
}

// GetScopes returns the granted scopes
func (r *ClientCredentialsTokenRequest) GetScopes() []string {
	return r.scopes
}

// ValidateClientCredentials validates client credentials (accept any non-empty credentials like legacy)
func ValidateClientCredentials(clientID, clientSecret string) error {
	if clientID == "" || clientSecret == "" {
		return ErrMissingClientCredentials
	}
	return nil
}
