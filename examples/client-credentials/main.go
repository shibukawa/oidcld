package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func main() {
	// Parse CLI arguments
	idpHost := flag.String("idp-host", "http://localhost:18888", "OIDC server URL")
	clientID := flag.String("client-id", "my-client-app", "OAuth 2.0 Client ID")
	flag.Parse()

	fmt.Printf("Using OIDC server: %s\n", *idpHost)
	fmt.Printf("Client ID: %s\n", *clientID)

	// Create certified OIDC client
	scopes := []string{oidc.ScopeOpenID, "read", "write"}
	client, err := rp.NewRelyingPartyOIDC(
		context.Background(),
		*idpHost,
		*clientID,
		"client-secret", // Default from oidcld.yaml
		"http://localhost:8080/callback",
		scopes,
	)
	if err != nil {
		log.Fatal("Failed to create OIDC client:", err)
	}

	fmt.Println("Requesting token...")

	// Get client credentials token
	params := url.Values{}
	token, err := rp.ClientCredentials(context.Background(), client, params)
	if err != nil {
		log.Fatal("Failed to get token:", err)
	}

	fmt.Println("Success!")
	fmt.Printf("Access Token: %s\n", token.AccessToken)
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expires In: %d seconds\n", int(token.Expiry.Sub(time.Now()).Seconds()))
}
