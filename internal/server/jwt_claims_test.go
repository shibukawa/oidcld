package server

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestBuildDeviceFlowIDTokenClaims_IncludesExpectedProfileAndEmailClaims(t *testing.T) {
	server := &Server{config: &config.Config{OIDCLD: config.OIDCLDConfig{Issuer: "https://issuer.example.com"}}}
	now := time.Unix(1700000000, 0)
	expiry := now.Add(time.Hour)

	claims := server.buildDeviceFlowIDTokenClaims(
		"test-client-id",
		"user1",
		config.User{
			DisplayName: "Test User",
			ExtraClaims: map[string]any{
				"given_name":  "Test",
				"family_name": "User",
				"email":       "user@example.com",
				"department":  "Engineering",
			},
		},
		[]string{"openid", "profile", "email"},
		now,
		expiry,
	)

	assert.Equal(t, "https://issuer.example.com", claims["iss"])
	assert.Equal(t, "user1", claims["sub"])
	aud, ok := claims["aud"].(jwt.ClaimStrings)
	assert.True(t, ok)
	assert.Equal(t, jwt.ClaimStrings{"test-client-id"}, aud)
	assert.Equal(t, "Test User", claims["name"])
	assert.Equal(t, "Test", claims["given_name"])
	assert.Equal(t, "User", claims["family_name"])
	assert.Equal(t, "user@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
	assert.Equal(t, "Engineering", claims["department"])
	assert.Equal(t, now.Unix(), claims["iat"].(int64))
	assert.Equal(t, now.Unix(), claims["nbf"].(int64))
	assert.Equal(t, expiry.Unix(), claims["exp"].(int64))
}
