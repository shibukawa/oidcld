package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

// createCORSMiddleware creates a CORS middleware with the given configuration
func createCORSMiddleware(corsConfig *config.CORSConfig) func(http.Handler) http.Handler {
	corsConfig = applyCORSDefaults(corsConfig)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if handleCORS(w, r, corsConfig) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func applyCORSDefaults(corsConfig *config.CORSConfig) *config.CORSConfig {
	if corsConfig == nil || !corsConfig.Enabled {
		return nil
	}

	result := &config.CORSConfig{
		Enabled: true,
		Origins: append([]string(nil), corsConfig.Origins...),
		Methods: append([]string(nil), corsConfig.Methods...),
		Headers: append([]string(nil), corsConfig.Headers...),
	}

	if len(result.Origins) == 0 {
		result.Origins = []string{"*"}
	}
	if len(result.Methods) == 0 {
		result.Methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	if len(result.Headers) == 0 {
		result.Headers = []string{"Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"}
	}

	return result
}

func handleCORS(w http.ResponseWriter, r *http.Request, corsConfig *config.CORSConfig) bool {
	corsConfig = applyCORSDefaults(corsConfig)
	if corsConfig == nil {
		return false
	}

	origin := r.Header.Get("Origin")
	if !isOriginAllowed(origin, corsConfig.Origins) {
		return false
	}

	setCORSHeaders(w, corsConfig, origin)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	if slices.Contains(allowedOrigins, "*") {
		return true
	}

	return slices.Contains(allowedOrigins, origin)
}

func setCORSHeaders(w http.ResponseWriter, corsConfig *config.CORSConfig, origin string) {
	if slices.Contains(corsConfig.Origins, "*") {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if len(corsConfig.Methods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsConfig.Methods, ", "))
	}

	if len(corsConfig.Headers) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsConfig.Headers, ", "))
	}

	w.Header().Set("Access-Control-Allow-Credentials", "true")
}
