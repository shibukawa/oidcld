package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

const (
	defaultIssuer   = "http://localhost:18888"
	defaultClientID = "device-flow"
	defaultScope    = "openid profile email"
)

func main() {
	fmt.Println("🔐 OpenID Connect Device Flow CLI Example")
	fmt.Println("==========================================")

	// Configuration
	issuer := getEnvOrDefault("OIDC_ISSUER", defaultIssuer)
	clientID := getEnvOrDefault("OIDC_CLIENT_ID", defaultClientID)
	scope := getEnvOrDefault("OIDC_SCOPE", defaultScope)

	fmt.Printf("📡 Issuer: %s\n", issuer)
	fmt.Printf("🆔 Client ID: %s\n", clientID)
	fmt.Printf("🔭 Scope: %s\n", scope)
	fmt.Println()

	ctx := context.Background()

	// Create OIDC relying party (client) - configure for device flow public client
	// For device flow, we need to ensure the client is treated as public
	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, "", "", []string{scope})
	if err != nil {
		log.Fatalf("❌ Failed to create OIDC client: %v", err)
	}

	// Step 1: Start device authorization flow
	fmt.Println("Step 1: Starting device authorization flow...")
	deviceAuth, err := rp.DeviceAuthorization(ctx, []string{scope}, provider, nil)
	if err != nil {
		log.Fatalf("❌ Device authorization failed: %v", err)
	}

	fmt.Println("✅ Device authorization successful!")
	fmt.Println()
	fmt.Println("📱 USER ACTION REQUIRED:")
	fmt.Printf("   1. Open your browser and go to: %s\n", deviceAuth.VerificationURI)
	fmt.Printf("   2. Enter this code: %s\n", deviceAuth.UserCode)
	if deviceAuth.VerificationURIComplete != "" {
		fmt.Printf("   3. Or use this direct link: %s\n", deviceAuth.VerificationURIComplete)
	}
	fmt.Println()
	fmt.Printf("⏰ Code expires in %d seconds\n", deviceAuth.ExpiresIn)
	fmt.Printf("🔄 Polling every %d seconds...\n", deviceAuth.Interval)
	fmt.Println()

	// Try to open browser automatically
	if deviceAuth.VerificationURIComplete != "" {
		if err := openBrowser(deviceAuth.VerificationURIComplete); err == nil {
			fmt.Println("🌐 Browser opened automatically")
		} else {
			fmt.Println("⚠️  Could not open browser automatically")
		}
	}
	fmt.Println()

	// Step 2: Poll for token
	fmt.Println("Step 2: Waiting for user authorization...")
	interval := time.Duration(deviceAuth.Interval) * time.Second
	token, err := rp.DeviceAccessToken(ctx, deviceAuth.DeviceCode, interval, provider)
	if err != nil {
		log.Fatalf("❌ Failed to get access token: %v", err)
	}

	fmt.Println("🎉 Authentication successful!")
	fmt.Println()
	fmt.Printf("🔑 Access Token: %s...\n", truncateToken(token.AccessToken))
	fmt.Printf("🆔 ID Token: %s...\n", truncateToken(token.IDToken))
	if token.RefreshToken != "" {
		fmt.Printf("🔄 Refresh Token: %s...\n", truncateToken(token.RefreshToken))
	}
	fmt.Printf("⏰ Expires in: %d seconds\n", token.ExpiresIn)
	fmt.Printf("🔭 Token Type: %s\n", token.TokenType)
	fmt.Println()

	// Step 3: Get user info (simplified - just show what we have)
	fmt.Println("Step 3: Token information:")
	fmt.Println("✅ Authentication completed successfully!")
	fmt.Printf("   🔑 Access Token: %s...\n", truncateToken(token.AccessToken))
	fmt.Printf("   🆔 ID Token: %s...\n", truncateToken(token.IDToken))
	if token.RefreshToken != "" {
		fmt.Printf("   🔄 Refresh Token: %s...\n", truncateToken(token.RefreshToken))
	}
	fmt.Printf("   ⏰ Expires in: %d seconds\n", token.ExpiresIn)
	fmt.Printf("   🔭 Token Type: %s\n", token.TokenType)
	if len(token.Scope) > 0 {
		fmt.Printf("   🔭 Scope: %s\n", token.Scope)
	}

	fmt.Println()
	fmt.Println("🎊 Device Flow completed successfully!")
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// truncateToken truncates a token for display
func truncateToken(token string) string {
	if len(token) > 20 {
		return token[:20] + "..."
	}
	return token
}

// openBrowser opens the default browser with the given URL
func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
