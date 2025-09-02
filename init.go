package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	cfgpkg "github.com/shibukawa/oidcld/internal/config"
)

// promptCertificateMethod asks user for certificate method (manual/ACME)
// and fills corresponding fields on InitCmd. Shared by standard and EntraID flows.
func promptCertificateMethod(reader *bufio.Reader, cmd *InitCmd) error {
	fmt.Println("1. Manual certificates (provide your own cert/key files)")
	fmt.Println("2. ACME (Let's Encrypt's protocol for automatic certificates)")
	fmt.Print("Choose certificate method [1/2]: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read certificate choice: %w", err)
	}
	choice = strings.TrimSpace(choice)
	switch choice {
	case "1", "":
		fmt.Println("Manual certificate configuration selected.")
		fmt.Println("You will need to provide certificate files when starting the server.")
		fmt.Println()
		fmt.Println("For local development, you can use mkcert:")
		fmt.Println("  1. Install mkcert: https://github.com/FiloSottile/mkcert")
		fmt.Println("  2. Run: mkcert -install")
		fmt.Println("  3. Generate certificates: mkcert localhost")
		fmt.Println("  4. Start server: ./oidcld serve --cert-file localhost.pem --key-file localhost-key.pem")
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

		fmt.Print("OIDC server domains for certificates (comma-separated) [localhost]: ")
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
	default:
		fmt.Println("Invalid choice, defaulting to manual certificates.")
		fmt.Println("You will need to provide certificate files when starting the server.")
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
	HTTPS    bool   `help:"Enable HTTPS mode (default for EntraID templates)"`
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

	// If run non-interactively (template specified) perform existence check
	if cmd.Template != "" && !cmd.Overwrite {
		if err := cmd.checkExistingFiles(); err != nil {
			return err
		}
	}

	// Determine mode from template
	mode := cfgpkg.ModeStandard
	switch cmd.Template {
	case "entraid-v1":
		mode = cfgpkg.ModeEntraIDv1
	case "entraid-v2":
		mode = cfgpkg.ModeEntraIDv2
	}

	// Create default config for selected mode
	cfg, err := cfgpkg.CreateDefaultConfig(mode)
	if err != nil {
		return fmt.Errorf("failed to create default config: %w", err)
	}

	// Apply init options (port / issuer / tenant / autocert)
	var domains []string
	if strings.TrimSpace(cmd.Domains) != "" {
		parts := strings.Split(cmd.Domains, ",")
		for _, p := range parts {
			d := strings.TrimSpace(p)
			if d != "" {
				domains = append(domains, d)
			}
		}
	}
	cfg.ApplyInitServerOptions(mode, &cfgpkg.InitServerOptions{
		TenantID:   cmd.TenantID,
		Port:       cmd.Port,
		Issuer:     cmd.Issuer,
		HTTPS:      cmd.HTTPS,
		Autocert:   cmd.Autocert,
		ACMEServer: cmd.ACMEServer,
		Domains:    domains,
		Email:      cmd.Email,
	})

	// Save configuration file
	if err := cfgpkg.SaveConfig(cmd.Config, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	// Success summary
	color.Green("✅ Initialization complete")
	fmt.Printf("  Config file: %s\n", cmd.Config)
	if cmd.Autocert {
		fmt.Printf("  ACME enabled (server: %s)\n", cmd.ACMEServer)
		fmt.Println("  Place any required cache dir or ensure ports 80/443 accessible.")
		fmt.Println("  (For a custom ACME like 'myencrypt', set --acme-server URL appropriately.)")
	} else if cmd.HTTPS {
		fmt.Println()
		fmt.Println("HTTPS enabled - provide certificate files when starting:")
		fmt.Println("  ./oidcld serve --cert-file <cert.pem> --key-file <key.pem>")
		fmt.Println()
		fmt.Println("For local development with mkcert:")
		fmt.Println("  1. Install mkcert: https://github.com/FiloSottile/mkcert")
		fmt.Println("  2. Run: mkcert -install")
		fmt.Println("  3. Generate: mkcert localhost")
		fmt.Println("  4. Start: ./oidcld serve --cert-file localhost.pem --key-file localhost-key.pem")
	}
	fmt.Println()
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

	// Overwrite confirmation
	if !cmd.Overwrite {
		filesToCheck := []string{cmd.Config}

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
			// Mark overwrite accepted so later run() skip duplicate existence check
			cmd.Overwrite = true
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
	if cmd.HTTPS {
		fmt.Printf("  HTTPS: enabled\n")
		if cmd.Autocert {
			fmt.Printf("  ACME: enabled\n")
			fmt.Printf("  ACME server: %s\n", cmd.ACMEServer)
			fmt.Printf("  domains: %s\n", cmd.Domains)
		}
	}
	fmt.Printf("  Config file: %s\n", cmd.Config)
	fmt.Println()

	return nil
}

// checkExistingFiles checks if configuration files already exist
func (cmd *InitCmd) checkExistingFiles() error {
	filesToCheck := []string{cmd.Config}

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

// (Automatic mkcert certificate generation removed by request; users are guided to run mkcert manually.)
