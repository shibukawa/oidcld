package server

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shibukawa/oidcld/internal/config"
)

func (s *Server) newDeviceFlowBaseClaims(clientID, userID string, issuedAt, expiresAt time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": s.config.OIDC.Issuer,
		"sub": userID,
		"aud": jwt.ClaimStrings{clientID},
		"exp": expiresAt.Unix(),
		"iat": issuedAt.Unix(),
		"nbf": issuedAt.Unix(),
	}
}

func (s *Server) buildDeviceFlowAccessTokenClaims(clientID, userID string, user config.User, scopes []string, issuedAt, expiresAt time.Time) jwt.MapClaims {
	claims := s.newDeviceFlowBaseClaims(clientID, userID, issuedAt, expiresAt)
	claims["scope"] = strings.Join(scopes, " ")
	claims["client_id"] = clientID
	maps.Copy(claims, user.ExtraClaims)
	return claims
}

func (s *Server) buildDeviceFlowIDTokenClaims(clientID, userID string, user config.User, scopes []string, issuedAt, expiresAt time.Time) jwt.MapClaims {
	claims := s.newDeviceFlowBaseClaims(clientID, userID, issuedAt, expiresAt)

	if slices.Contains(scopes, "profile") {
		claims["name"] = user.DisplayName
		if givenName, ok := user.ExtraClaims["given_name"]; ok {
			claims["given_name"] = givenName
		}
		if familyName, ok := user.ExtraClaims["family_name"]; ok {
			claims["family_name"] = familyName
		}
	}

	if slices.Contains(scopes, "email") {
		if email, ok := user.ExtraClaims["email"]; ok {
			claims["email"] = email
			claims["email_verified"] = true
		}
	}

	for key, value := range user.ExtraClaims {
		if key != "given_name" && key != "family_name" && key != "email" {
			claims[key] = value
		}
	}

	return claims
}

func (s *Server) buildDeviceFlowRefreshTokenClaims(clientID, userID string, scopes []string, issuedAt, expiresAt time.Time) jwt.MapClaims {
	claims := s.newDeviceFlowBaseClaims(clientID, userID, issuedAt, expiresAt)
	claims["token_use"] = "refresh"
	claims["scope"] = strings.Join(scopes, " ")
	return claims
}
