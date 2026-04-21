package server

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shibukawa/oidcld/internal/config"
)

var errReverseProxyGatewayMissingClaims = errors.New("reverse proxy gateway missing claims")

type compiledReverseProxyGateway struct {
	requiredEnabled        bool
	requiredClaims         map[string]any
	forwardClaimsAsHeaders map[string]string
	replayAuthorization    bool
}

type reverseProxyGatewayClaimCheck struct {
	requiredClaims   map[string]any
	tokenClaims      map[string]any
	missingScopes    []string
	missingAudiences []string
	mismatchedClaims map[string]any
}

func newCompiledReverseProxyGateway(gateway *config.ReverseProxyGateway) *compiledReverseProxyGateway {
	if gateway == nil {
		return nil
	}
	item := &compiledReverseProxyGateway{
		requiredEnabled:        gateway.Required.Enabled,
		requiredClaims:         map[string]any{},
		forwardClaimsAsHeaders: map[string]string{},
		replayAuthorization:    gateway.ReplayAuthorization == nil || *gateway.ReplayAuthorization,
	}
	maps.Copy(item.requiredClaims, gateway.Required.Claims)
	maps.Copy(item.forwardClaimsAsHeaders, gateway.ForwardClaimsAsHeaders)
	if len(item.requiredClaims) > 0 {
		item.requiredEnabled = true
	}
	return item
}

func (s *Server) authorizeReverseProxyRoute(w http.ResponseWriter, r *http.Request, gateway *compiledReverseProxyGateway) bool {
	if gateway == nil {
		return true
	}
	if !gateway.requiredEnabled && len(gateway.forwardClaimsAsHeaders) == 0 && !gateway.replayAuthorization {
		return true
	}

	tokenValue := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tokenValue == "" || tokenValue == r.Header.Get("Authorization") {
		s.logger.Warn("Reverse proxy gateway denied request",
			"reason", "missing_bearer_token",
			"method", r.Method,
			"path", r.URL.Path,
			"host", r.Host)
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenValue, claims, func(token *jwt.Token) (any, error) {
		return &s.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.config.OIDC.Issuer), jwt.WithIssuedAt())
	if err != nil || parsed == nil || !parsed.Valid {
		s.logger.Warn("Reverse proxy gateway denied request",
			"reason", "invalid_token",
			"method", r.Method,
			"path", r.URL.Path,
			"host", r.Host,
			"error", err,
			"issuer", stringifyClaimValue(claims["iss"]),
			"subject", stringifyClaimValue(claims["sub"]),
			"client_id", stringifyClaimValue(claims["client_id"]))
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false
	}

	claimCheck := gateway.evaluateClaims(claims)
	if !claimCheck.allowed() {
		s.logger.Warn("Reverse proxy gateway denied request",
			"reason", "claims_mismatch",
			"method", r.Method,
			"path", r.URL.Path,
			"host", r.Host,
			"issuer", stringifyClaimValue(claims["iss"]),
			"subject", stringifyClaimValue(claims["sub"]),
			"client_id", stringifyClaimValue(claims["client_id"]),
			"required_claims", claimCheck.requiredClaims,
			"token_claims", claimCheck.tokenClaims,
			"missing_scopes", claimCheck.missingScopes,
			"missing_audiences", claimCheck.missingAudiences,
			"mismatched_claims", claimCheck.mismatchedClaims)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	for claim, header := range gateway.forwardClaimsAsHeaders {
		if value, ok := claims[claim]; ok {
			r.Header.Set(header, stringifyClaimValue(value))
		}
	}

	return true
}

func (g *compiledReverseProxyGateway) evaluateClaims(claims jwt.MapClaims) reverseProxyGatewayClaimCheck {
	check := reverseProxyGatewayClaimCheck{
		requiredClaims:   map[string]any{},
		tokenClaims:      map[string]any{},
		mismatchedClaims: map[string]any{},
	}
	if g == nil || !g.requiredEnabled || len(g.requiredClaims) == 0 {
		return check
	}
	check.requiredClaims = cloneClaimsMap(g.requiredClaims)

	for claim, expected := range g.requiredClaims {
		switch claim {
		case "scope":
			check.tokenClaims[claim] = tokenScopes(claims)
			missing := missingExpectedValues(tokenScopes(claims), expectedValues(expected))
			if len(missing) > 0 {
				check.missingScopes = append(check.missingScopes, missing...)
			}
		case "aud":
			check.tokenClaims[claim] = jwtAudiences(claims["aud"])
			missing := missingExpectedValues(jwtAudiences(claims["aud"]), expectedValues(expected))
			if len(missing) > 0 {
				check.missingAudiences = append(check.missingAudiences, missing...)
			}
		default:
			actualValues := claimValues(claims[claim])
			if len(actualValues) == 0 {
				check.tokenClaims[claim] = nil
			} else if len(actualValues) == 1 {
				check.tokenClaims[claim] = actualValues[0]
			} else {
				check.tokenClaims[claim] = actualValues
			}
			if !claimMatchesRequirement(actualValues, expected) {
				check.mismatchedClaims[claim] = expected
			}
		}
	}

	return check
}

func (c reverseProxyGatewayClaimCheck) allowed() bool {
	return len(c.missingScopes) == 0 && len(c.missingAudiences) == 0 && len(c.mismatchedClaims) == 0
}

func (s *Server) replayReverseProxyAuthorization(claims jwt.MapClaims) (string, error) {
	if claims == nil {
		return "", errReverseProxyGatewayMissingClaims
	}

	now := time.Now()
	replayedClaims := jwt.MapClaims{}
	for key, value := range claims {
		switch key {
		case "iat", "nbf", "exp", "jti":
			continue
		default:
			replayedClaims[key] = value
		}
	}
	replayedClaims["iss"] = s.config.OIDC.Issuer
	replayedClaims["iat"] = now.Unix()
	replayedClaims["nbf"] = now.Unix()
	replayedClaims["exp"] = now.Add(time.Duration(s.config.OIDC.ExpiredIn) * time.Second).Unix()
	replayedClaims["jti"] = uuid.NewString()

	return s.signJWT(replayedClaims)
}

func (s *Server) maybeReplayReverseProxyAuthorization(r *http.Request, gateway *compiledReverseProxyGateway) {
	if r == nil || !shouldReplayReverseProxyAuthorization(gateway) {
		return
	}

	tokenValue := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tokenValue == "" || tokenValue == r.Header.Get("Authorization") {
		return
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenValue, claims, func(token *jwt.Token) (any, error) {
		return &s.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.config.OIDC.Issuer), jwt.WithIssuedAt())
	if err != nil || parsed == nil || !parsed.Valid {
		return
	}

	replayedToken, replayErr := s.replayReverseProxyAuthorization(claims)
	if replayErr != nil {
		s.logger.Warn("Reverse proxy gateway failed to replay authorization",
			"method", r.Method,
			"path", r.URL.Path,
			"host", r.Host,
			"error", replayErr)
		return
	}
	r.Header.Set("Authorization", "Bearer "+replayedToken)
}

func shouldReplayReverseProxyAuthorization(gateway *compiledReverseProxyGateway) bool {
	if gateway == nil {
		return true
	}
	return gateway.replayAuthorization
}

func expectedValues(value any) []string {
	switch typed := value.(type) {
	case string:
		typed = strings.TrimSpace(typed)
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []string:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
		return result
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" || text == "<nil>" {
			return nil
		}
		return []string{text}
	}
}

func claimValues(raw any) []string {
	switch value := raw.(type) {
	case string:
		text := strings.TrimSpace(value)
		if text == "" {
			return nil
		}
		return []string{text}
	case []string:
		result := make([]string, 0, len(value))
		for _, item := range value {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
		return result
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		text := strings.TrimSpace(fmt.Sprint(raw))
		if text == "" || text == "<nil>" {
			return nil
		}
		return []string{text}
	}
}

func claimMatchesRequirement(actualValues []string, expected any) bool {
	requiredValues := expectedValues(expected)
	if len(requiredValues) == 0 {
		return true
	}
	switch expected.(type) {
	case []string, []any:
		if len(actualValues) == 0 {
			return false
		}
		if len(actualValues) == 1 && len(requiredValues) > 1 {
			return false
		}
		return len(missingExpectedValues(actualValues, requiredValues)) == 0
	default:
		return len(actualValues) == 1 && actualValues[0] == requiredValues[0]
	}
}

func missingExpectedValues(actualValues, requiredValues []string) []string {
	var missing []string
	for _, required := range requiredValues {
		if !slices.Contains(actualValues, required) {
			missing = append(missing, required)
		}
	}
	return missing
}

func tokenScopes(claims jwt.MapClaims) []string {
	if claims == nil {
		return nil
	}
	raw, ok := claims["scope"]
	if !ok {
		return nil
	}
	scopeValue, ok := raw.(string)
	if !ok {
		return nil
	}
	return strings.Fields(scopeValue)
}

func jwtAudiences(raw any) []string {
	switch value := raw.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				result = append(result, text)
			}
		}
		return result
	case []string:
		result := make([]string, 0, len(value))
		for _, item := range value {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
		return result
	default:
		return nil
	}
}

func stringifyClaimValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		return strings.Join(typed, " ")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprint(value)
	}
}
