package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shibukawa/oidcld/internal/config"
)

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	assert.Equal(t, 3, len(parts))

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	assert.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)

	return claims
}

func newAudienceClaimTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	return &Server{
		config:     cfg,
		privateKey: privateKey,
	}
}

func signAudienceClaimTestJWT(t *testing.T, privateKey *rsa.PrivateKey, audience any) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user1",
		"aud": audience,
	})
	token.Header["kid"] = "oidcld-key"

	signed, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	return signed
}

func TestSignJWT_SingleAudienceDefaultsToString(t *testing.T) {
	server := newAudienceClaimTestServer(t, &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:              "https://issuer.example.com",
			AudienceClaimFormat: config.AudienceClaimFormatString,
		},
	})

	token, err := server.signJWT(jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user1",
		"aud": jwt.ClaimStrings{"test-client-id"},
	})
	assert.NoError(t, err)

	claims := decodeJWTPayload(t, token)
	assert.Equal(t, "test-client-id", claims["aud"])
}

func TestSignJWT_SingleAudienceCanBeForcedToArray(t *testing.T) {
	server := newAudienceClaimTestServer(t, &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:              "https://issuer.example.com",
			AudienceClaimFormat: config.AudienceClaimFormatArray,
		},
	})

	token, err := server.signJWT(jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user1",
		"aud": jwt.ClaimStrings{"test-client-id"},
	})
	assert.NoError(t, err)

	claims := decodeJWTPayload(t, token)
	aud, ok := claims["aud"].([]any)
	assert.True(t, ok)
	assert.Equal(t, 1, len(aud))
	assert.Equal(t, "test-client-id", aud[0])
}

func TestSignJWT_MultipleAudiencesRemainArray(t *testing.T) {
	server := newAudienceClaimTestServer(t, &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:              "https://issuer.example.com",
			AudienceClaimFormat: config.AudienceClaimFormatString,
		},
	})

	token, err := server.signJWT(jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user1",
		"aud": jwt.ClaimStrings{"aud-1", "aud-2"},
	})
	assert.NoError(t, err)

	claims := decodeJWTPayload(t, token)
	aud, ok := claims["aud"].([]any)
	assert.True(t, ok)
	assert.Equal(t, []any{"aud-1", "aud-2"}, aud)
}

func TestGenerateDeviceFlowTokens_UsesConfiguredAudienceClaimFormat(t *testing.T) {
	server := newAudienceClaimTestServer(t, &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:              "https://issuer.example.com",
			ExpiredIn:           3600,
			RefreshTokenEnabled: true,
			RefreshTokenExpiry:  86400,
			AudienceClaimFormat: config.AudienceClaimFormatArray,
		},
	})

	accessToken, idToken, refreshToken, err := server.generateDeviceFlowTokens("test-client-id", "user1", config.User{
		DisplayName: "Test User",
		ExtraClaims: map[string]any{
			"email": "user@example.com",
		},
	}, []string{"openid", "email"})
	assert.NoError(t, err)
	assert.NotZero(t, accessToken)
	assert.NotZero(t, idToken)
	assert.NotZero(t, refreshToken)

	for _, token := range []string{accessToken, idToken, refreshToken} {
		claims := decodeJWTPayload(t, token)
		aud, ok := claims["aud"].([]any)
		assert.True(t, ok)
		assert.Equal(t, []any{"test-client-id"}, aud)
	}
}

func TestRewriteJWTTokenAudience_SingleAudienceArrayToString(t *testing.T) {
	server := newAudienceClaimTestServer(t, &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:              "https://issuer.example.com",
			AudienceClaimFormat: config.AudienceClaimFormatString,
		},
	})

	original := signAudienceClaimTestJWT(t, server.privateKey, []string{"test-client-id"})
	rewritten, err := server.rewriteJWTTokenAudience(original)
	assert.NoError(t, err)

	claims := decodeJWTPayload(t, rewritten)
	assert.Equal(t, "test-client-id", claims["aud"])
}

func TestNormalizeTokenResponsePayload_RewritesProviderIssuedJWTs(t *testing.T) {
	server := newAudienceClaimTestServer(t, &config.Config{
		OIDCLD: config.OIDCLDConfig{
			Issuer:              "https://issuer.example.com",
			AudienceClaimFormat: config.AudienceClaimFormatString,
		},
	})

	providerStyleToken := signAudienceClaimTestJWT(t, server.privateKey, []string{"test-client-id"})
	payload := map[string]any{
		"access_token":  providerStyleToken,
		"id_token":      providerStyleToken,
		"refresh_token": providerStyleToken,
		"token_type":    "Bearer",
	}

	err := server.normalizeTokenResponsePayload(payload)
	assert.NoError(t, err)

	for _, field := range []string{"access_token", "id_token", "refresh_token"} {
		token, ok := payload[field].(string)
		assert.True(t, ok)

		claims := decodeJWTPayload(t, token)
		assert.Equal(t, "test-client-id", claims["aud"])
	}
}
