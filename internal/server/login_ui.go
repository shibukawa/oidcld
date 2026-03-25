package server

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/shibukawa/oidcld/internal/config"
	"github.com/yuin/goldmark"
	gast "github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var loginInfoMarkdownRenderer = goldmark.New(
	goldmark.WithExtensions(
		extension.Table,
	),
	goldmark.WithParserOptions(
		parser.WithASTTransformers(
			util.Prioritized(loginInfoLinkTransformer{}, 100),
		),
	),
	goldmark.WithRendererOptions(
		gmhtml.WithHardWraps(),
	),
)

const oidcldGitHubRepositoryURL = "https://github.com/shibukawa/oidcld"

type LoginPageConfig struct {
	AuthRequestID    string
	ClientID         string
	Scopes           []string
	EnvironmentTitle string
	AccentColor      string
	HeaderTextColor  string
	InfoPanelHTML    string
}

type loginInfoLinkTransformer struct{}

func (loginInfoLinkTransformer) Transform(node *gast.Document, _ text.Reader, _ parser.Context) {
	_ = gast.Walk(node, func(node gast.Node, entering bool) (gast.WalkStatus, error) {
		if !entering {
			return gast.WalkContinue, nil
		}

		link, ok := node.(*gast.Link)
		if !ok {
			return gast.WalkContinue, nil
		}

		if !isAllowedMarkdownDestination(string(link.Destination)) {
			link.Destination = []byte("#")
		}

		return gast.WalkContinue, nil
	})
}

func isAllowedMarkdownDestination(destination string) bool {
	trimmedDestination := strings.TrimSpace(destination)
	if trimmedDestination == "" {
		return false
	}
	if strings.HasPrefix(trimmedDestination, "//") {
		return false
	}

	parsedURL, err := url.Parse(trimmedDestination)
	if err != nil {
		return false
	}
	if parsedURL.Scheme == "" {
		return true
	}

	switch strings.ToLower(parsedURL.Scheme) {
	case "http", "https", "mailto":
		return true
	default:
		return false
	}
}

func (s *Server) renderLoginInfoPanel(loginUI *config.LoginUIConfig) (string, error) {
	if loginUI == nil || loginUI.EffectiveInfoMarkdownFile() == "" {
		return "", nil
	}

	markdownContent, err := os.ReadFile(loginUI.EffectiveInfoMarkdownFile())
	if err != nil {
		return "", err
	}

	renderedMarkdown, err := renderLoginInfoMarkdown(markdownContent)
	if err != nil {
		return "", err
	}

	styleAttr := ""
	if accentColor := loginUI.EffectiveAccentColor(); accentColor != "" {
		styleAttr = fmt.Sprintf(` style="border-top-color: %s;"`, html.EscapeString(accentColor))
	}

	return fmt.Sprintf(`<section class="info-panel"%s>%s</section>`, styleAttr, renderedMarkdown), nil
}

func renderLoginInfoWarning(message string) string {
	return fmt.Sprintf(`<section class="info-panel info-panel-warning"><p>%s</p></section>`, html.EscapeString(message))
}

func renderLoginInfoMarkdown(markdownContent []byte) (string, error) {
	var renderedHTML bytes.Buffer
	if err := loginInfoMarkdownRenderer.Convert(markdownContent, &renderedHTML); err != nil {
		return "", err
	}
	return renderedHTML.String(), nil
}

func (s *Server) renderLoginPage(w http.ResponseWriter, config LoginPageConfig) {
	accentColor := strings.TrimSpace(config.AccentColor)
	if accentColor == "" {
		accentColor = "#DCE6F6"
	}

	headerTextColor := strings.TrimSpace(config.HeaderTextColor)
	if headerTextColor == "" {
		headerTextColor = "#111111"
	}

	headerTitle := "OIDCLD: Login Page"
	if title := strings.TrimSpace(config.EnvironmentTitle); title != "" {
		headerTitle = fmt.Sprintf("(%s) %s", title, headerTitle)
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <style>
        :root {
            color-scheme: light;
            --login-accent: %s;
            --login-header-text: %s;
            --login-page-bg: #f3f4f6;
            --login-surface: #ffffff;
            --login-border: #d6d9df;
            --login-text: #111827;
            --login-muted: #6b7280;
            --login-shadow: 0 16px 40px rgba(15, 23, 42, 0.08);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: var(--login-page-bg);
            color: var(--login-text);
        }
        .login-shell {
            min-height: 100vh;
            width: 100%%;
        }
        .login-header {
            width: 100%%;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px 32px;
            background: var(--login-accent);
            color: var(--login-header-text);
            border-bottom: 1px solid rgba(17, 24, 39, 0.12);
        }
        .login-header-title {
            margin: 0;
            max-width: min(100%%, 880px);
            padding: 0 76px;
            font-size: clamp(1.15rem, 3.4vw, 2.1rem);
            font-weight: 700;
            line-height: 1.2;
            text-align: center;
            text-wrap: balance;
        }
        .login-header-link {
            position: absolute;
            top: 50%%;
            right: 32px;
            transform: translateY(-50%%);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 48px;
            height: 48px;
            border-radius: 999px;
            color: #111827;
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid rgba(17, 24, 39, 0.18);
            text-decoration: none;
            flex-shrink: 0;
            box-shadow: 0 4px 10px rgba(15, 23, 42, 0.10);
        }
        .login-header-link:hover {
            background: #ffffff;
        }
        .login-header-link svg {
            width: 26px;
            height: 26px;
        }
        .login-content {
            width: min(1180px, 100%%);
            margin: 0 auto;
            padding: 28px 32px 36px;
        }
        .login-main {
            display: grid;
            grid-template-columns: minmax(280px, 360px) minmax(0, 1fr);
            gap: 28px;
            align-items: start;
        }
        .users-panel,
        .request-card,
        .info-panel {
            background: var(--login-surface);
            border: 1px solid var(--login-border);
            border-radius: 18px;
            box-shadow: var(--login-shadow);
        }
        .users-panel {
            padding: 18px 18px 16px;
        }
        .users-panel-title {
            margin: 0 0 18px;
            padding-bottom: 10px;
            border-bottom: 3px solid #111827;
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }
        .users-panel-list {
            max-height: min(65vh, 720px);
            overflow-y: auto;
            padding-right: 4px;
        }
        .user-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .user-list li + li {
            margin-top: 10px;
        }
        .user-button {
            display: block;
            width: 100%%;
            padding: 12px 14px;
            border: 1px solid #d9dee7;
            border-radius: 10px;
            background: #ffffff;
            cursor: pointer;
            text-align: left;
            font-size: 15px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
        }
        .user-button:hover {
            background-color: #f8fafc;
            border-color: #bfc7d4;
        }
        .user-button:focus {
            outline: 2px solid var(--login-accent);
            outline-offset: 2px;
        }
        .user-name {
            font-weight: bold;
            display: block;
        }
        .user-email {
            color: var(--login-muted);
            font-size: 0.82rem;
            display: block;
            margin-top: 4px;
        }
        .info-column {
            display: grid;
            gap: 16px;
            align-items: start;
        }
        .request-card {
            padding: 16px 18px 18px;
        }
        .request-card-title {
            display: inline-block;
            margin: 0 0 14px;
            padding: 6px 12px;
            border-radius: 8px;
            background: var(--login-accent);
            color: var(--login-header-text);
            font-size: 0.95rem;
            font-weight: 700;
        }
        .request-card-row + .request-card-row {
            margin-top: 10px;
        }
        .request-card-label {
            font-weight: 700;
            margin-right: 6px;
        }
        .request-card-value,
        .request-card-scopes {
            word-break: break-word;
        }
        .info-panel {
            padding: 18px;
            text-align: left;
            border-top-width: 4px;
        }
        .info-panel h1, .info-panel h2, .info-panel h3, .info-panel h4, .info-panel h5, .info-panel h6 {
            margin-top: 0;
        }
        .info-panel p, .info-panel ul, .info-panel ol, .info-panel pre, .info-panel table {
            margin-bottom: 14px;
        }
        .info-panel ul, .info-panel ol {
            padding-left: 22px;
        }
        .info-panel code {
            background: rgba(0, 0, 0, 0.06);
            padding: 2px 4px;
            border-radius: 4px;
        }
        .info-panel pre {
            background: #f6f8fa;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
        }
        .info-panel table {
            width: 100%%;
            border-collapse: collapse;
        }
        .info-panel th, .info-panel td {
            border: 1px solid #d0d7de;
            padding: 8px 10px;
        }
        .info-panel a {
            color: #0f4c81;
        }
        .info-panel-warning {
            background-color: #fff4e5;
            border-color: #e2b35b;
            color: #5f3b00;
        }
        @media (max-width: 960px) {
            .login-header {
                padding: 20px 20px 18px;
            }
            .login-header-title {
                padding: 0 56px 0 16px;
                font-size: clamp(1.05rem, 5vw, 1.65rem);
                text-align: left;
            }
            .login-header-link {
                right: 20px;
                width: 40px;
                height: 40px;
            }
            .login-content {
                padding: 20px 18px 28px;
            }
            .login-main {
                grid-template-columns: 1fr;
            }
            .users-panel-list {
                max-height: none;
                overflow: visible;
                padding-right: 0;
            }
            .users-panel-title {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-shell">
        <header class="login-header">
            <h1 class="login-header-title">%s</h1>
            <a class="login-header-link" href="%s" target="_blank" rel="noopener noreferrer" aria-label="OIDCLD GitHub repository">
                <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                    <path d="M12 2C6.48 2 2 6.58 2 12.23c0 4.52 2.87 8.35 6.84 9.7.5.1.68-.22.68-.49 0-.24-.01-1.04-.01-1.88-2.78.62-3.37-1.2-3.37-1.2-.45-1.18-1.11-1.49-1.11-1.49-.91-.64.07-.63.07-.63 1 .07 1.53 1.05 1.53 1.05.9 1.56 2.36 1.11 2.94.85.09-.67.35-1.11.64-1.36-2.22-.26-4.56-1.14-4.56-5.08 0-1.12.39-2.03 1.03-2.75-.11-.26-.45-1.3.1-2.72 0 0 .84-.28 2.75 1.05A9.36 9.36 0 0 1 12 6.88c.85 0 1.71.12 2.51.36 1.91-1.33 2.75-1.05 2.75-1.05.55 1.42.21 2.46.1 2.72.64.72 1.03 1.63 1.03 2.75 0 3.95-2.34 4.81-4.57 5.06.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.8 0 .27.18.59.69.49A10.09 10.09 0 0 0 22 12.23C22 6.58 17.52 2 12 2Z"></path>
                </svg>
            </a>
        </header>
        <main class="login-content">
            <div class="login-main">
                <section class="users-panel">
                    <h2 class="users-panel-title">Select Users</h2>
                    <div class="users-panel-list">
                        <ul class="user-list">%s
                        </ul>
                    </div>
                </section>
                <aside class="info-column">
                    <section class="request-card">
                        <p class="request-card-title">Request Information</p>
                        <div class="request-card-row"><span class="request-card-label">Client:</span><span class="request-card-value">%s</span></div>
                        <div class="request-card-row"><span class="request-card-label">Scopes:</span><span class="request-card-scopes">%s</span></div>
                    </section>
                    %s
                </aside>
            </div>
        </main>
    </div>
</body>
</html>`,
		html.EscapeString(headerTitle),
		html.EscapeString(accentColor),
		html.EscapeString(headerTextColor),
		html.EscapeString(headerTitle),
		html.EscapeString(oidcldGitHubRepositoryURL),
		s.renderLoginUserList(config.AuthRequestID),
		html.EscapeString(config.ClientID),
		html.EscapeString(strings.Join(config.Scopes, " ")),
		config.InfoPanelHTML,
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(builder.String()))
}

func (s *Server) renderLoginUserList(authRequestID string) string {
	var builder strings.Builder

	for userID, user := range s.config.Users {
		email := getEmailFromClaims(user.ExtraClaims)
		fmt.Fprintf(&builder, `
                            <li>
                                <form method="POST" action="" style="margin: 0;">
                                    <input type="hidden" name="authRequestID" value="%s">
                                    <button type="submit" name="userID" value="%s" class="user-button" aria-label="%s">
                                        <span class="user-name">%s</span>
                                        <span class="user-email">%s</span>
                                    </button>
                                </form>
                            </li>`,
			html.EscapeString(authRequestID),
			html.EscapeString(userID),
			html.EscapeString(userID),
			html.EscapeString(user.DisplayName),
			html.EscapeString(email),
		)
	}

	return builder.String()
}
