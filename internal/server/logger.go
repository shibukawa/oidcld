package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/shibukawa/oidcld/internal/config"
)

// Logger provides colorful, pretty logging for the OIDC server
type Logger struct {
	// Color functions
	success *color.Color
	info    *color.Color
	warning *color.Color
	error   *color.Color
	debug   *color.Color

	// Special colors
	highlight *color.Color
	url       *color.Color
	key       *color.Color
	value     *color.Color
}

// NewLogger creates a new colorful logger
func NewLogger() *Logger {
	return &Logger{
		success:   color.New(color.FgGreen, color.Bold),
		info:      color.New(color.FgCyan, color.Bold),
		warning:   color.New(color.FgYellow, color.Bold),
		error:     color.New(color.FgRed, color.Bold),
		debug:     color.New(color.FgMagenta),
		highlight: color.New(color.FgWhite, color.Bold),
		url:       color.New(color.FgBlue, color.Underline),
		key:       color.New(color.FgYellow),
		value:     color.New(color.FgGreen),
	}
}

// ServerStarting logs server startup with beautiful formatting
func (l *Logger) ServerStarting(addr, issuer string, https bool, entraid *config.EntraIDConfig, httpMetadataAddr string, accessFilter accessFilterStartupInfo) {
	fmt.Println()
	l.printBanner()
	fmt.Println()

	if https {
		l.success.Print("🔒 HTTPS Server Starting")
	} else {
		l.info.Print("🚀 HTTP Server Starting")
	}
	fmt.Println()

	l.printKeyValue("📍 Address", addr)
	l.printKeyValue("🌐 Issuer", issuer)
	if accessFilter.Enabled {
		l.printKeyValue("🛡 Access Filter", fmt.Sprintf("enabled (extra allowlist: %d, max forwarded hops: %d)", accessFilter.ExtraAllowedIPs, accessFilter.MaxForwardedHops))
	} else {
		l.printKeyValue("🛡 Access Filter", "disabled")
	}
	l.printKeyValue("⏰ Started", time.Now().Format("2006-01-02 15:04:05"))
	endpoints, tenants := startupEndpointsForIssuer(issuer, entraid)

	fmt.Println()
	l.info.Println("📋 Available Endpoints:")
	l.printEndpoint("Discovery", endpoints.Discovery)
	l.printEndpoint("Authorization", endpoints.Authorize)
	l.printEndpoint("Token", endpoints.Token)
	l.printEndpoint("UserInfo", endpoints.UserInfo)
	l.printEndpoint("JWKS", endpoints.JWKS)
	l.printEndpoint("Device Flow", endpoints.DeviceAuthorization)
	l.printEndpoint("Introspection", endpoints.Introspection)
	l.printEndpoint("Revocation", endpoints.Revocation)
	l.printEndpoint("End Session", endpoints.Logout)
	l.printEndpoint("Health Check", endpoints.HealthCheck)
	if len(tenants) > 0 {
		l.printKeyValue("Tenant", strings.Join(tenants, ", ")+" (or omitted)")
	}

	if httpMetadataAddr != "" {
		if metadataIssuer := config.HTTPMetadataIssuer(issuer, httpMetadataAddr); metadataIssuer != "" {
			httpEndpoints, metadataTenants := startupEndpointsForIssuer(metadataIssuer, entraid)

			fmt.Println()
			l.info.Println("🔎 HTTP Metadata Companion:")
			l.printKeyValue("📍 Address", httpMetadataAddr)
			l.printKeyValue("🌐 Base URL", metadataIssuer)
			l.printKeyValue("🔒 Scope", "Discovery, JWKS, Health Check only")
			l.printEndpoint("Discovery", httpEndpoints.Discovery)
			l.printEndpoint("JWKS", httpEndpoints.JWKS)
			l.printEndpoint("Health Check", httpEndpoints.HealthCheck)
			if len(metadataTenants) > 0 {
				l.printKeyValue("Tenant", strings.Join(metadataTenants, ", ")+" (or omitted)")
			}
		}
	}

	fmt.Println()
	l.success.Println("✅ Server ready to accept connections!")
	l.printSeparator()
}

func startupEndpointsForIssuer(issuer string, entraid *config.EntraIDConfig) (entraIDStartupDisplay, []string) {
	startupDisplay, hasStartupDisplay := entraIDStartupDisplayForIssuer(issuer, entraid)
	if hasStartupDisplay {
		return startupDisplay, startupDisplay.Tenants
	}
	endpoints := oidcEndpointsForRequest(issuer, entraid, entraIDRequestInfo{})
	return startupDisplayFromEndpoints(endpoints, nil), nil
}

// ConfigReloaded logs successful configuration reload
func (l *Logger) ConfigReloaded(configFile string, changes []string) {
	l.printSectionTitle(l.info, "🔄 Configuration Reloaded")

	l.printKeyValue("📄 File", configFile)
	l.printCurrentTime()

	if len(changes) > 0 {
		fmt.Println()
		l.info.Println("📝 Changes Applied:")
		for _, change := range changes {
			fmt.Print("   • ")
			l.value.Println(change)
		}
	}

	l.printSectionFooter(l.success, "✅ Configuration updated successfully!")
}

// ConfigReloadFailed logs configuration reload failure
func (l *Logger) ConfigReloadFailed(configFile string, err error) {
	l.printSectionTitle(l.error, "❌ Configuration Reload Failed")

	l.printKeyValue("📄 File", configFile)
	l.printCurrentTime()
	l.printKeyValue("💥 Error", err.Error())

	l.printSectionFooter(l.warning, "⚠️  Using previous configuration")
}

// RequestLog logs HTTP requests with colors
func (l *Logger) RequestLog(method, path string, statusCode int, duration time.Duration) {
	l.printRequestLogPrefix(method, path, statusCode, duration)
	fmt.Println()
}

// RequestLogWithCORS logs HTTP requests with CORS debugging information
func (l *Logger) RequestLogWithCORS(method, path string, statusCode int, duration time.Duration, origin, corsOrigin string) {
	l.printRequestLogPrefix(method, path, statusCode, duration)
	l.debug.Print(" ")

	// Add CORS debugging info
	if origin != "" {
		l.key.Print("Origin: ")
		l.value.Print(origin)
		if corsOrigin != "" {
			l.key.Print(" → CORS: ")
			if corsOrigin == origin || corsOrigin == "*" {
				l.success.Print(corsOrigin)
			} else {
				l.warning.Print(corsOrigin)
			}
		} else {
			l.error.Print(" → No CORS")
		}
	}
	fmt.Println()
}

// DeviceFlowStarted logs device flow initiation
func (l *Logger) DeviceFlowStarted(clientID, userCode, deviceCode string) {
	l.printSectionTitle(l.info, "📱 Device Flow Started")

	l.printKeyValue("🆔 Client", clientID)
	l.printKeyValue("👤 User Code", userCode)
	l.printKeyValue("📟 Device Code", deviceCode[:8]+"...")
	l.printCurrentTime()

	l.printSectionFooter(l.success, "🎯 Waiting for user authorization...")
}

// DeviceFlowCompleted logs device flow completion
func (l *Logger) DeviceFlowCompleted(userCode, userID string, approved bool) {
	fmt.Println()
	if approved {
		l.success.Print("✅ Device Flow Approved")
	} else {
		l.warning.Print("❌ Device Flow Denied")
	}
	fmt.Println()

	l.printKeyValue("👤 User Code", userCode)
	l.printKeyValue("🧑 User ID", userID)
	l.printCurrentTime()

	if approved {
		l.printSectionFooter(l.success, "🎉 Authorization successful!")
	} else {
		l.printSectionFooter(l.warning, "🚫 Authorization denied")
	}
}

// TokenIssued logs token issuance
func (l *Logger) TokenIssued(clientID, userID, grantType string, scopes []string) {
	l.printSectionTitle(l.success, "🎫 Token Issued")

	l.printKeyValue("🆔 Client", clientID)
	l.printKeyValue("🧑 User", userID)
	l.printKeyValue("🔑 Grant Type", grantType)
	l.printKeyValue("🎯 Scopes", strings.Join(scopes, ", "))
	l.printCurrentTime()

	l.printSectionFooter(l.success, "✨ Token generated successfully!")
}

// Error logs errors with formatting
func (l *Logger) Error(message string, err error) {
	l.printSectionTitleInline(l.error, "❌ Error: ", message)

	if err != nil {
		l.printKeyValue("💥 Details", err.Error())
	}
	l.printCurrentTime()

	l.printSeparator()
}

// Warning logs warnings with formatting
func (l *Logger) Warning(message string) {
	l.printSectionTitleInline(l.warning, "⚠️  Warning: ", message)
	l.printCurrentTime()
	l.printSeparator()
}

// Info logs info messages with formatting
func (l *Logger) Info(message string) {
	l.printSectionTitleInline(l.info, "ℹ️  Info: ", message)
	l.printCurrentTime()
	l.printSeparator()
}

// printBanner prints the application banner
func (l *Logger) printBanner() {
	banner := `
 ██████╗ ██╗██████╗  ██████╗██╗     ██████╗ 
██╔═══██╗██║██╔══██╗██╔════╝██║     ██╔══██╗
██║   ██║██║██║  ██║██║     ██║     ██║  ██║
██║   ██║██║██║  ██║██║     ██║     ██║  ██║
╚██████╔╝██║██████╔╝╚██████╗███████╗██████╔╝
 ╚═════╝ ╚═╝╚═════╝  ╚═════╝╚══════╝╚═════╝ 
                                            
OpenID Connect Test Identity Provider`

	l.highlight.Println(banner)
}

// printKeyValue prints a key-value pair with colors
func (l *Logger) printKeyValue(key, value string) {
	l.key.Printf("   %-12s ", key+":")
	l.value.Println(value)
}

// printEndpoint prints an endpoint with colors
func (l *Logger) printEndpoint(name, url string) {
	l.key.Printf("   %-15s ", name+":")
	l.url.Println(url)
}

// printSeparator prints a visual separator
func (l *Logger) printSeparator() {
	l.debug.Println(strings.Repeat("─", 80))
}

func (l *Logger) printSectionTitle(style *color.Color, title string) {
	fmt.Println()
	style.Print(title)
	fmt.Println()
}

func (l *Logger) printSectionTitleInline(style *color.Color, prefix, message string) {
	fmt.Println()
	style.Print(prefix)
	style.Println(message)
}

func (l *Logger) printCurrentTime() {
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))
}

func (l *Logger) printSectionFooter(style *color.Color, message string) {
	fmt.Println()
	style.Println(message)
	l.printSeparator()
}

func (l *Logger) requestStatusStyle(statusCode int) (*color.Color, string) {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return l.success, "✅"
	case statusCode >= 300 && statusCode < 400:
		return l.info, "🔄"
	case statusCode >= 400 && statusCode < 500:
		return l.warning, "⚠️"
	default:
		return l.error, "❌"
	}
}

func (l *Logger) printRequestLogPrefix(method, path string, statusCode int, duration time.Duration) {
	statusColor, statusEmoji := l.requestStatusStyle(statusCode)
	timestamp := time.Now().Format("15:04:05")
	l.debug.Printf("[%s] ", timestamp)
	statusColor.Printf("%s %d ", statusEmoji, statusCode)
	l.highlight.Printf("%-6s ", method)
	l.url.Printf("%-30s ", path)
	l.debug.Printf("(%v)", duration)
}
