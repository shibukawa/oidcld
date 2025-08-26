package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// promptCertificateMethod asks user for certificate method (mkcert/autocert/manual)
// and fills corresponding fields on InitCmd. Shared by standard and EntraID flows.
func promptCertificateMethod(reader *bufio.Reader, cmd *InitCmd) error {
	fmt.Println("1. mkcert (local development certificates)")
	fmt.Println("2. ACME/autocert (automatic certificates from ACME server)")
	fmt.Println("3. Manual certificates (provide your own cert/key files)")
	fmt.Print("Choose certificate method [1/2/3]: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read certificate choice: %w", err)
	}
	choice = strings.TrimSpace(choice)
	switch choice {
	case "1", "":
		cmd.Mkcert = true
	case "2":
		cmd.Autocert = true
		fmt.Print("ACME server URL [http://localhost:14000]: ")
		acmeServer, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read ACME server: %w", err)
		}
		acmeServer = strings.TrimSpace(acmeServer)
		if acmeServer == "" {
			acmeServer = "http://localhost:14000"
		}
		cmd.ACMEServer = acmeServer

		fmt.Print("Domains (comma-separated) [localhost]: ")
		domains, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read domains: %w", err)
		}
		domains = strings.TrimSpace(domains)
		if domains == "" {
			domains = "localhost"
		}
		cmd.Domains = domains

		fmt.Print("Email for ACME registration [admin@localhost]: ")
		email, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read email: %w", err)
		}
		email = strings.TrimSpace(email)
		if email == "" {
			email = "admin@localhost"
		}
		cmd.Email = email
	case "3":
		fmt.Println("Manual certificate configuration selected.")
		fmt.Println("You will need to provide certificate files when starting the server.")
	default:
		fmt.Println("Invalid choice, defaulting to mkcert.")
		cmd.Mkcert = true
	}
	return nil
}

// InitCmd represents the command to initialize configuration
type InitCmd struct {
	Config   string `arg:"" help:"Configuration file path" default:"oidcld.yaml"`
	Template string `help:"Template to use" enum:"standard,entraid-v1,entraid-v2," default:""`
	TenantID string `help:"Tenant ID for EntraID templates"`
	Port     string `short:"p" help:"Port number for issuer URL"`
	Issuer   string `help:"Custom issuer URL"`
	Cert     string `help:"Generate certificate with algorithm" enum:"RS256,RS384,RS512,ES256,ES384,ES512," default:""`
	HTTPS    bool   `help:"Enable HTTPS mode (default for EntraID templates)"`
	Mkcert   bool   `help:"Generate mkcert certificates for HTTPS"`
	// ACME/Autocert settings
	Autocert   bool   `help:"Enable autocert for automatic HTTPS certificates"`
	ACMEServer string `help:"ACME server URL for autocert" env:"OIDCLD_ACME_DIRECTORY_URL"`
	Domains    string `help:"Comma-separated list of domains for autocert certificates"`
	Email      string `help:"Email address for ACME registration" env:"OIDCLD_ACME_EMAIL"`
	Overwrite  bool   `short:"w" help:"Overwrite existing files without confirmation"`
}

// Run executes the initialization command with the provided configuration.
func (cmd *InitCmd) Run() error {
	// Run wizard if template is not specified
	if cmd.Template == "" {
		if err := cmd.runWizard(); err != nil {
			return fmt.Errorf("wizard failed: %w", err)
		}
	}

	// Check for existing files unless overwrite is specified
	if !cmd.Overwrite {
		if err := cmd.checkExistingFiles(); err != nil {
			return err
		}
	}

	// (Original success summary removed in refactor; will be re-added later with proper cfg context)
	return nil
}

// runWizard runs an interactive wizard to configure the initialization
func (cmd *InitCmd) runWizard() error {
	reader := bufio.NewReader(os.Stdin)

	color.Cyan("OIDCLD Configuration Wizard")
	color.Cyan("=============================")
	color.Cyan("")

	// Template selection
	fmt.Println("Select template:")
	fmt.Println("1. Standard OpenID Connect (default)")
	fmt.Println("2. EntraID/AzureAD v1.0")
	fmt.Println("3. EntraID/AzureAD v2.0")
	color.Yellow("Enter choice [1-3] (default: 1): ")

	templateChoice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read template choice: %w", err)
	}
	templateChoice = strings.TrimSpace(templateChoice)

	switch templateChoice {
	case "", "1":
		cmd.Template = "standard"
	case "2":
		cmd.Template = "entraid-v1"
	case "3":
		cmd.Template = "entraid-v2"
	default:
		return fmt.Errorf("%w: %s", ErrInvalidTemplateChoice, templateChoice)
	}

	// EntraID-specific configuration
	if cmd.Template == "entraid-v1" || cmd.Template == "entraid-v2" {
		color.Yellow("Enter Tenant ID (optional): ")
		tenantID, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read tenant ID: %w", err)
		}
		cmd.TenantID = strings.TrimSpace(tenantID)
		cmd.HTTPS = true // EntraID requires HTTPS

		// Ask about mkcert even for EntraID templates (reuse shared helper)
		fmt.Println()
		fmt.Println("HTTPS Certificate Configuration:")
		if err := promptCertificateMethod(reader, cmd); err != nil {
			return err
		}
	}

	// HTTPS configuration for standard template
	if cmd.Template == "standard" {
		fmt.Println()
		fmt.Println("HTTPS Configuration:")
		fmt.Print("Enable HTTPS? [y/N]: ")
		httpsChoice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read HTTPS choice: %w", err)
		}
		httpsChoice = strings.TrimSpace(strings.ToLower(httpsChoice))
		cmd.HTTPS = httpsChoice == "y" || httpsChoice == "yes"

		if cmd.HTTPS {
			fmt.Println()
			fmt.Println("HTTPS Certificate Options:")
			if err := promptCertificateMethod(reader, cmd); err != nil {
				return err
			}
		}
	}

	// Port configuration
	if cmd.Template == "standard" {
		fmt.Print("Enter port number (default: 18888): ")
		port, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read port: %w", err)
		}
		port = strings.TrimSpace(port)
		if port != "" {
			if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
				return fmt.Errorf("%w: %s", ErrInvalidPortNumber, port)
			}
			cmd.Port = port
		}
	}

	// Custom issuer
	fmt.Print("Enter custom issuer URL (optional): ")
	issuer, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read issuer: %w", err)
	}
	cmd.Issuer = strings.TrimSpace(issuer)

	// Certificate generation
	fmt.Println()
	fmt.Println("Certificate generation:")
	fmt.Println("1. No certificate generation (default)")
	fmt.Println("2. RS256 (RSA 2048-bit)")
	fmt.Println("3. RS384 (RSA 3072-bit)")
	fmt.Println("4. RS512 (RSA 4096-bit)")
	fmt.Println("5. ES256 (ECDSA P-256)")
	fmt.Println("6. ES384 (ECDSA P-384)")
	fmt.Println("7. ES512 (ECDSA P-521)")
	fmt.Print("Enter choice [1-7] (default: 1): ")

	certChoice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read certificate choice: %w", err)
	}
	certChoice = strings.TrimSpace(certChoice)

	switch certChoice {
	case "", "1":
		cmd.Cert = ""
	case "2":
		cmd.Cert = "RS256"
	case "3":
		cmd.Cert = "RS384"
	case "4":
		cmd.Cert = "RS512"
	case "5":
		cmd.Cert = "ES256"
	case "6":
		cmd.Cert = "ES384"
	case "7":
		cmd.Cert = "ES512"
	default:
		return fmt.Errorf("%w: %s", ErrInvalidCertificateChoice, certChoice)
	}

	// Overwrite confirmation
	if !cmd.Overwrite {
		filesToCheck := []string{cmd.Config}
		if cmd.Cert != "" {
			filesToCheck = append(filesToCheck, ".oidcld.key", ".oidcld.pub.key")
		}
		if cmd.Mkcert || cmd.HTTPS {
			filesToCheck = append(filesToCheck, "localhost.pem", "localhost-key.pem")
		}

		var existingFiles []string
		for _, file := range filesToCheck {
			if _, err := os.Stat(file); err == nil {
				existingFiles = append(existingFiles, file)
			}
		}

		if len(existingFiles) > 0 {
			fmt.Printf("\nThe following files already exist:\n")
			for _, file := range existingFiles {
				fmt.Printf("  - %s\n", file)
			}
			fmt.Print("Overwrite existing files? [y/N]: ")
			overwriteChoice, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read overwrite choice: %w", err)
			}
			overwriteChoice = strings.TrimSpace(strings.ToLower(overwriteChoice))
			if overwriteChoice != "y" && overwriteChoice != "yes" {
				return ErrOperationCancelled
			}
		}
	}

	// Configuration summary
	fmt.Println()
	color.Cyan("Configuration summary:")
	fmt.Printf("  Template: %s\n", cmd.Template)
	if cmd.TenantID != "" {
		fmt.Printf("  Tenant ID: %s\n", cmd.TenantID)
	}
	if cmd.Port != "" {
		fmt.Printf("  Port: %s\n", cmd.Port)
	}
	if cmd.Issuer != "" {
		fmt.Printf("  Issuer: %s\n", cmd.Issuer)
	}
	if cmd.Cert != "" {
		fmt.Printf("  Certificate: %s\n", cmd.Cert)
	}
	if cmd.HTTPS {
		fmt.Printf("  HTTPS: enabled\n")
		if cmd.Mkcert {
			fmt.Printf("  mkcert: enabled\n")
		}
		if cmd.Autocert {
			fmt.Printf("  autocert: enabled\n")
			fmt.Printf("  ACME server: %s\n", cmd.ACMEServer)
			fmt.Printf("  domains: %s\n", cmd.Domains)
		}
	}
	fmt.Printf("  Config file: %s\n", cmd.Config)
	fmt.Println()

	return nil
}

// checkExistingFiles checks if configuration or key files already exist
func (cmd *InitCmd) checkExistingFiles() error {
	filesToCheck := []string{cmd.Config}

	// Add key files if certificate generation is requested
	if cmd.Cert != "" {
		filesToCheck = append(filesToCheck, ".oidcld.key", ".oidcld.pub.key")
	}

	// Add mkcert certificate files if HTTPS is enabled
	if cmd.Mkcert || cmd.HTTPS {
		filesToCheck = append(filesToCheck, "localhost.pem", "localhost-key.pem")
	}

	var existingFiles []string
	for _, file := range filesToCheck {
		if _, err := os.Stat(file); err == nil {
			existingFiles = append(existingFiles, file)
		}
	}

	if len(existingFiles) > 0 {
		color.Red("❌ The following files already exist and would be overwritten:")
		for _, file := range existingFiles {
			fmt.Printf("  - %s\n", file)
		}
		fmt.Println("Please remove them or use different file names")
		return fmt.Errorf("%w:\n  %s", ErrFilesExist, strings.Join(existingFiles, "\n  "))
	}

	return nil
}

// generateMkcertCertificates generates TLS certificates using mkcert
// (generateMkcertCertificates removed; certificate generation via mkcert will be handled elsewhere if reintroduced)
