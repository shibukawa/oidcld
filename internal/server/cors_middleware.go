package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
)

// createCORSMiddleware creates a CORS middleware with the given configuration
func createCORSMiddleware(corsConfig *config.CORSConfig) func(http.Handler) http.Handler {
	// Apply defaults to CORS configuration
	corsConfig = applyCORSDefaults(corsConfig)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CORS if disabled
			if !corsConfig.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			if !isOriginAllowed(origin, corsConfig.AllowedOrigins) {
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers
			setCORSHeaders(w, corsConfig, origin)

			// Handle preflight OPTIONS request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Continue with the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// applyCORSDefaults applies default values to CORS configuration
func applyCORSDefaults(corsConfig *config.CORSConfig) *config.CORSConfig {
	if corsConfig == nil {
		return &config.CORSConfig{
			Enabled: false,
		}
	}

	// Create a copy to avoid modifying the original
	result := &config.CORSConfig{
		Enabled:        corsConfig.Enabled,
		AllowedOrigins: corsConfig.AllowedOrigins,
		AllowedMethods: corsConfig.AllowedMethods,
		AllowedHeaders: corsConfig.AllowedHeaders,
	}

	// Apply defaults if enabled
	if result.Enabled {
		if len(result.AllowedOrigins) == 0 {
			result.AllowedOrigins = []string{"*"}
		}
		if len(result.AllowedMethods) == 0 {
			result.AllowedMethods = []string{"GET", "POST", "OPTIONS"}
		}
		if len(result.AllowedHeaders) == 0 {
			result.AllowedHeaders = []string{"Content-Type", "Authorization"}
		}
	}

	return result
}

// isOriginAllowed checks if the given origin is allowed
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	// Check for wildcard
	if slices.Contains(allowedOrigins, "*") {
		return true
	}

	// Check for exact match
	return slices.Contains(allowedOrigins, origin)
}

// setCORSHeaders sets the appropriate CORS headers
func setCORSHeaders(w http.ResponseWriter, corsConfig *config.CORSConfig, origin string) {
	// Set Access-Control-Allow-Origin
	if slices.Contains(corsConfig.AllowedOrigins, "*") {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	// Set Access-Control-Allow-Methods
	if len(corsConfig.AllowedMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsConfig.AllowedMethods, ", "))
	}

	// Set Access-Control-Allow-Headers
	if len(corsConfig.AllowedHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsConfig.AllowedHeaders, ", "))
	}

	// Set Access-Control-Allow-Credentials
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}
