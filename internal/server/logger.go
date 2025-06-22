package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
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
func (l *Logger) ServerStarting(addr, issuer string, https bool) {
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
	l.printKeyValue("⏰ Started", time.Now().Format("2006-01-02 15:04:05"))

	fmt.Println()
	l.info.Println("📋 Available Endpoints:")
	l.printEndpoint("Discovery", issuer+"/.well-known/openid-configuration")
	l.printEndpoint("Authorization", issuer+"/authorize")
	l.printEndpoint("Token", issuer+"/token")
	l.printEndpoint("UserInfo", issuer+"/userinfo")
	l.printEndpoint("JWKS", issuer+"/keys")
	l.printEndpoint("Device Flow", issuer+"/device_authorization")
	l.printEndpoint("Introspection", issuer+"/oauth/introspect")
	l.printEndpoint("Revocation", issuer+"/revoke")
	l.printEndpoint("End Session", issuer+"/end_session")
	l.printEndpoint("Health Check", issuer+"/health")

	fmt.Println()
	l.success.Println("✅ Server ready to accept connections!")
	l.printSeparator()
}

// ConfigReloaded logs successful configuration reload
func (l *Logger) ConfigReloaded(configFile string, changes []string) {
	fmt.Println()
	l.info.Print("🔄 Configuration Reloaded")
	fmt.Println()

	l.printKeyValue("📄 File", configFile)
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))

	if len(changes) > 0 {
		fmt.Println()
		l.info.Println("📝 Changes Applied:")
		for _, change := range changes {
			fmt.Print("   • ")
			l.value.Println(change)
		}
	}

	fmt.Println()
	l.success.Println("✅ Configuration updated successfully!")
	l.printSeparator()
}

// ConfigReloadFailed logs configuration reload failure
func (l *Logger) ConfigReloadFailed(configFile string, err error) {
	fmt.Println()
	l.error.Print("❌ Configuration Reload Failed")
	fmt.Println()

	l.printKeyValue("📄 File", configFile)
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))
	l.printKeyValue("💥 Error", err.Error())

	fmt.Println()
	l.warning.Println("⚠️  Using previous configuration")
	l.printSeparator()
}

// RequestLog logs HTTP requests with colors
func (l *Logger) RequestLog(method, path string, statusCode int, duration time.Duration) {
	var statusColor *color.Color
	var statusEmoji string

	switch {
	case statusCode >= 200 && statusCode < 300:
		statusColor = l.success
		statusEmoji = "✅"
	case statusCode >= 300 && statusCode < 400:
		statusColor = l.info
		statusEmoji = "🔄"
	case statusCode >= 400 && statusCode < 500:
		statusColor = l.warning
		statusEmoji = "⚠️"
	default:
		statusColor = l.error
		statusEmoji = "❌"
	}

	timestamp := time.Now().Format("15:04:05")
	l.debug.Printf("[%s] ", timestamp)
	statusColor.Printf("%s %d ", statusEmoji, statusCode)
	l.highlight.Printf("%-6s ", method)
	l.url.Printf("%-30s ", path)
	l.debug.Printf("(%v)", duration)
	fmt.Println()
}

// RequestLogWithCORS logs HTTP requests with CORS debugging information
func (l *Logger) RequestLogWithCORS(method, path string, statusCode int, duration time.Duration, origin, corsOrigin string) {
	var statusColor *color.Color
	var statusEmoji string

	switch {
	case statusCode >= 200 && statusCode < 300:
		statusColor = l.success
		statusEmoji = "✅"
	case statusCode >= 300 && statusCode < 400:
		statusColor = l.info
		statusEmoji = "🔄"
	case statusCode >= 400 && statusCode < 500:
		statusColor = l.warning
		statusEmoji = "⚠️"
	default:
		statusColor = l.error
		statusEmoji = "❌"
	}

	timestamp := time.Now().Format("15:04:05")
	l.debug.Printf("[%s] ", timestamp)
	statusColor.Printf("%s %d ", statusEmoji, statusCode)
	l.highlight.Printf("%-6s ", method)
	l.url.Printf("%-30s ", path)
	l.debug.Printf("(%v) ", duration)

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
	fmt.Println()
	l.info.Print("📱 Device Flow Started")
	fmt.Println()

	l.printKeyValue("🆔 Client", clientID)
	l.printKeyValue("👤 User Code", userCode)
	l.printKeyValue("📟 Device Code", deviceCode[:8]+"...")
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))

	fmt.Println()
	l.success.Println("🎯 Waiting for user authorization...")
	l.printSeparator()
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
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))

	fmt.Println()
	if approved {
		l.success.Println("🎉 Authorization successful!")
	} else {
		l.warning.Println("🚫 Authorization denied")
	}
	l.printSeparator()
}

// TokenIssued logs token issuance
func (l *Logger) TokenIssued(clientID, userID, grantType string, scopes []string) {
	fmt.Println()
	l.success.Print("🎫 Token Issued")
	fmt.Println()

	l.printKeyValue("🆔 Client", clientID)
	l.printKeyValue("🧑 User", userID)
	l.printKeyValue("🔑 Grant Type", grantType)
	l.printKeyValue("🎯 Scopes", strings.Join(scopes, ", "))
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))

	fmt.Println()
	l.success.Println("✨ Token generated successfully!")
	l.printSeparator()
}

// Error logs errors with formatting
func (l *Logger) Error(message string, err error) {
	fmt.Println()
	l.error.Print("❌ Error: ")
	l.error.Println(message)

	if err != nil {
		l.printKeyValue("💥 Details", err.Error())
	}
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))

	l.printSeparator()
}

// Warning logs warnings with formatting
func (l *Logger) Warning(message string) {
	fmt.Println()
	l.warning.Print("⚠️  Warning: ")
	l.warning.Println(message)
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))
	l.printSeparator()
}

// Info logs info messages with formatting
func (l *Logger) Info(message string) {
	fmt.Println()
	l.info.Print("ℹ️  Info: ")
	l.info.Println(message)
	l.printKeyValue("⏰ Time", time.Now().Format("15:04:05"))
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
