package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shibukawa/oidcld/internal/config"
	"github.com/shibukawa/oidcld/internal/server/adminassets"
)

var ErrAdminConsolePortRequired = errors.New("admin console port is required")
var adminReverseProxyLogsHeartbeatInterval = 20 * time.Second

type adminStatusResponse struct {
	Issuer               string                      `json:"issuer"`
	AccessFilterEnabled  bool                        `json:"accessFilterEnabled"`
	HTTPSExpected        bool                        `json:"httpsExpected"`
	AutocertEnabled      bool                        `json:"autocertEnabled"`
	ReverseProxyEnabled  bool                        `json:"reverseProxyEnabled"`
	BrowserListeners     *adminBrowserListeners      `json:"browserListeners,omitempty"`
	AdminConsole         *adminConsoleStatusResponse `json:"adminConsole,omitempty"`
	OIDC                 *adminOIDCStatusResponse    `json:"oidc,omitempty"`
	SelfSignedTLS        *selfSignedTLSStatus        `json:"selfSignedTls,omitempty"`
	UsersCount           int                         `json:"usersCount"`
	ValidScopes          []string                    `json:"validScopes"`
	StaticAssetsResolved bool                        `json:"staticAssetsResolved"`
}

type adminConsoleStatusResponse struct {
	Port        string `json:"port"`
	BindAddress string `json:"bindAddress"`
}

type adminBrowserListeners struct {
	OIDC         *adminBrowserListenerStatus `json:"oidc,omitempty"`
	ReverseProxy *adminBrowserListenerStatus `json:"reverseProxy,omitempty"`
}

type adminBrowserListenerStatus struct {
	Scheme string `json:"scheme"`
	Port   string `json:"port"`
}

type adminOIDCStatusResponse struct {
	Mode                string                   `json:"mode"`
	TLSSource           string                   `json:"tlsSource"`
	AccessFilter        string                   `json:"accessFilter"`
	PKCERequired        bool                     `json:"pkceRequired"`
	NonceRequired       bool                     `json:"nonceRequired"`
	ExpiredIn           int                      `json:"expiredIn"`
	AudienceClaimFormat string                   `json:"audClaimFormat"`
	RefreshTokenEnabled bool                     `json:"refreshTokenEnabled"`
	RefreshTokenExpiry  int                      `json:"refreshTokenExpiry"`
	EndSessionEnabled   bool                     `json:"endSessionEnabled"`
	Endpoints           adminOIDCEndpointSummary `json:"endpoints"`
	Tenants             []string                 `json:"tenants,omitempty"`
}

type adminOIDCEndpointSummary struct {
	Discovery           string `json:"discovery"`
	Authorize           string `json:"authorize"`
	Token               string `json:"token"`
	UserInfo            string `json:"userInfo"`
	DeviceAuthorization string `json:"deviceAuthorization"`
	JWKS                string `json:"jwks"`
	Logout              string `json:"logout"`
	HealthCheck         string `json:"healthCheck"`
}

type selfSignedTLSStatus struct {
	Enabled     bool     `json:"enabled"`
	CADir       string   `json:"caDir"`
	Domains     []string `json:"domains"`
	CACertTTL   string   `json:"caCertTtl"`
	LeafCertTTL string   `json:"leafCertTtl"`
	Ready       bool     `json:"ready"`
	Reason      string   `json:"reason,omitempty"`
}

type adminUsersResponse struct {
	Users []adminUserSummary `json:"users"`
}

type adminReverseProxyResponse struct {
	LogRetention   int                     `json:"logRetention"`
	IgnoreLogPaths []string                `json:"ignoreLogPaths"`
	Hosts          []adminReverseProxyHost `json:"hosts"`
}

type adminReverseProxyHost struct {
	Host               string                   `json:"host"`
	DefaultVirtualHost bool                     `json:"defaultVirtualHost"`
	TLSSource          string                   `json:"tlsSource"`
	Routes             []adminReverseProxyRoute `json:"routes"`
}

type adminReverseProxyRoute struct {
	Path                       string         `json:"path"`
	Label                      string         `json:"label"`
	RouteType                  string         `json:"routeType"`
	Target                     string         `json:"target"`
	SPAFallback                bool           `json:"spaFallback"`
	RewritePathPrefix          string         `json:"rewritePathPrefix,omitempty"`
	GatewayEnabled             bool           `json:"gatewayEnabled"`
	GatewayRequired            map[string]any `json:"gatewayRequired,omitempty"`
	GatewayReplayAuthorization bool           `json:"gatewayReplayAuthorization"`
	MockPreferExamples         bool           `json:"mockPreferExamples"`
	MockDefaultStatus          string         `json:"mockDefaultStatus,omitempty"`
}

type adminReverseProxyLogsResponse struct {
	Entries []reverseProxyLogSummary `json:"entries"`
}

type adminUserSummary struct {
	ID               string         `json:"id"`
	DisplayName      string         `json:"displayName"`
	ExtraClaims      map[string]any `json:"extraClaims"`
	ExtraValidScopes []string       `json:"extraValidScopes,omitempty"`
}

type adminCertificateIssueRequest struct {
	Organization string `json:"organization"`
	DomainLabel  string `json:"domainLabel"`
	TTL          string `json:"ttl"`
	NotBefore    string `json:"notBefore"`
}

func ConsoleURL(bindAddress, port string) string {
	host := strings.TrimSpace(bindAddress)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "localhost"
	}
	if strings.TrimSpace(port) == "" {
		return ""
	}
	return fmt.Sprintf("http://%s/console/", net.JoinHostPort(host, strings.TrimSpace(port)))
}

func (s *Server) AdminHandler() http.Handler {
	consoleMux := http.NewServeMux()
	consoleMux.HandleFunc("/console/api/status", s.handleAdminStatus)
	consoleMux.HandleFunc("/console/api/openid-connect/users", s.handleAdminUsers)
	consoleMux.HandleFunc("/console/api/certificates", s.handleAdminCertificates)
	consoleMux.HandleFunc("/console/api/certificates/issue", s.handleAdminIssueCertificate)
	consoleMux.HandleFunc("/console/api/reverse-proxy", s.handleAdminReverseProxy)
	consoleMux.HandleFunc("/console/api/reverse-proxy/logs", s.handleAdminReverseProxyLogs)
	consoleMux.HandleFunc("/console/api/reverse-proxy/logs/", s.handleAdminReverseProxyLogDetail)
	consoleMux.HandleFunc("/console/api/reverse-proxy/logs/stream", s.handleAdminReverseProxyLogsStream)
	consoleMux.HandleFunc("/console/api/reverse-proxy/logs/replay", s.handleAdminReverseProxyLogsReplay)
	consoleMux.HandleFunc("/console/api/downloads/certificate-installer.zip", s.handleAdminCertificateInstallerDownload)
	consoleMux.HandleFunc("/console/api/downloads/root-ca.pem", s.handleAdminRootCADownload)
	consoleMux.HandleFunc("/console/api/downloads/install.sh", s.handleAdminUnixInstallScript)
	consoleMux.HandleFunc("/console/api/downloads/uninstall.sh", s.handleAdminUnixUninstallScript)
	consoleMux.HandleFunc("/console/api/downloads/install.ps1", s.handleAdminWindowsInstallScript)
	consoleMux.HandleFunc("/console/api/downloads/uninstall.ps1", s.handleAdminWindowsUninstallScript)
	consoleMux.Handle("/console/", s.adminStaticHandler())
	consoleMux.HandleFunc("/console", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console/", http.StatusPermanentRedirect)
	})

	metadataHandler := s.ReadOnlyHTTPHandler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			http.Redirect(w, r, "/console/", http.StatusPermanentRedirect)
		case isConsolePath(r.URL.Path):
			consoleMux.ServeHTTP(w, r)
		case s.shouldServeConsoleMetadata(r.URL.Path):
			metadataHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	return s.adminLocalOnlyMiddleware(handler)
}

func (s *Server) StartAdmin(bindAddress, port string) error {
	if strings.TrimSpace(port) == "" {
		return ErrAdminConsolePortRequired
	}
	address := net.JoinHostPort(strings.TrimSpace(bindAddress), strings.TrimSpace(port))
	server := &http.Server{
		Addr:    address,
		Handler: s.AdminHandler(),
	}
	return server.ListenAndServe()
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, _ *http.Request) {
	endpoints, tenants := startupEndpointsForIssuer(s.config.OIDC.Issuer, s.config.EntraID)
	response := adminStatusResponse{
		Issuer:              s.config.OIDC.Issuer,
		AccessFilterEnabled: s.config.AccessFilter != nil && s.config.AccessFilter.Enabled,
		HTTPSExpected:       strings.HasPrefix(s.config.OIDC.Issuer, "https://") || (s.config.Autocert != nil && s.config.Autocert.Enabled),
		AutocertEnabled:     s.config.Autocert != nil && s.config.Autocert.Enabled,
		ReverseProxyEnabled: s.config.ReverseProxy != nil && len(s.config.ReverseProxy.Hosts) > 0,
		UsersCount:          len(s.config.Users),
		ValidScopes:         append([]string(nil), s.config.OIDC.ValidScopes...),
		OIDC: &adminOIDCStatusResponse{
			Mode:                startupModeLabel(s.config.EntraID),
			TLSSource:           adminTLSSource(s.config),
			AccessFilter:        formatAccessFilterStartupInfo(s.access.startupInfo()),
			PKCERequired:        s.config.OIDC.PKCERequired,
			NonceRequired:       s.config.OIDC.NonceRequired,
			ExpiredIn:           s.config.OIDC.ExpiredIn,
			AudienceClaimFormat: s.config.OIDC.NormalizedAudienceClaimFormat(),
			RefreshTokenEnabled: s.config.OIDC.RefreshTokenEnabled,
			RefreshTokenExpiry:  s.config.OIDC.RefreshTokenExpiry,
			EndSessionEnabled:   s.config.OIDC.EndSessionEnabled,
			Tenants:             append([]string(nil), tenants...),
			Endpoints: adminOIDCEndpointSummary{
				Discovery:           endpoints.Discovery,
				Authorize:           endpoints.Authorize,
				Token:               endpoints.Token,
				UserInfo:            endpoints.UserInfo,
				DeviceAuthorization: endpoints.DeviceAuthorization,
				JWKS:                endpoints.JWKS,
				Logout:              endpoints.Logout,
				HealthCheck:         endpoints.HealthCheck,
			},
		},
	}

	if cfg := s.config.Console; cfg != nil {
		response.AdminConsole = &adminConsoleStatusResponse{
			Port:        s.consolePort,
			BindAddress: cfg.BindAddress,
		}
	}
	oidcScheme, _, oidcPort, ok := config.IssuerURLParts(s.config.OIDC.Issuer)
	if ok {
		response.BrowserListeners = &adminBrowserListeners{
			OIDC: &adminBrowserListenerStatus{
				Scheme: oidcScheme,
				Port:   oidcPort,
			},
		}
	}
	if scheme, err := s.config.ReverseProxyListenerScheme(); err == nil && scheme != "" {
		if response.BrowserListeners == nil {
			response.BrowserListeners = &adminBrowserListeners{}
		}
		response.BrowserListeners.ReverseProxy = &adminBrowserListenerStatus{
			Scheme: scheme,
		}
		for _, host := range s.config.ReverseProxy.Hosts {
			if host.IsDefaultVirtualHost() {
				continue
			}
			if port := host.Port(); port != "" {
				response.BrowserListeners.ReverseProxy.Port = port
				break
			}
		}
	}
	if cfg := s.config.CertificateAuthority; cfg != nil {
		response.SelfSignedTLS = &selfSignedTLSStatus{
			Enabled:     true,
			CADir:       cfg.CADir,
			Domains:     append([]string(nil), cfg.Domains...),
			CACertTTL:   cfg.CACertTTL,
			LeafCertTTL: cfg.LeafCertTTL,
			Ready:       false,
			Reason:      "Managed CA issuance is not wired into HTTPS startup yet.",
		}
	}

	if _, _, ok := s.findAdminDistFS(); ok {
		response.StaticAssetsResolved = true
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, _ *http.Request) {
	userIDs := make([]string, 0, len(s.config.Users))
	for id := range s.config.Users {
		userIDs = append(userIDs, id)
	}
	sort.Strings(userIDs)

	response := adminUsersResponse{
		Users: make([]adminUserSummary, 0, len(userIDs)),
	}
	for _, id := range userIDs {
		user := s.config.Users[id]
		response.Users = append(response.Users, adminUserSummary{
			ID:               id,
			DisplayName:      user.DisplayName,
			ExtraClaims:      cloneClaimsMap(user.ExtraClaims),
			ExtraValidScopes: append([]string(nil), user.ExtraValidScopes...),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminReverseProxy(w http.ResponseWriter, _ *http.Request) {
	response := adminReverseProxyResponse{}
	if s.config.ReverseProxy != nil {
		response.LogRetention = s.config.ReverseProxy.LogRetention
		response.IgnoreLogPaths = append([]string(nil), s.config.ReverseProxy.IgnoreLogPaths...)
		for _, host := range s.config.ReverseProxy.Hosts {
			item := adminReverseProxyHost{
				Host:               host.DisplayHost(),
				DefaultVirtualHost: host.IsDefaultVirtualHost(),
				TLSSource:          adminReverseProxyTLSSource(s.config, host),
			}
			for _, route := range host.Routes {
				target := route.TargetURL
				routeType := "proxy"
				gatewayRequired := map[string]any(nil)
				gatewayReplayAuthorization := false
				if route.Gateway != nil {
					gatewayRequired = cloneClaimsMap(route.Gateway.Required.Claims)
					gatewayReplayAuthorization = route.Gateway.ReplayAuthorization == nil || *route.Gateway.ReplayAuthorization
				}
				if route.StaticDir != "" {
					target = route.ResolvedStaticDir()
					routeType = "static"
				} else if route.OpenAPIFile != "" {
					target = route.ResolvedOpenAPIFile()
					routeType = "mock"
				}
				item.Routes = append(item.Routes, adminReverseProxyRoute{
					Path:                       route.Path,
					Label:                      route.ResolvedLabel(),
					RouteType:                  routeType,
					Target:                     target,
					SPAFallback:                route.SPAFallback,
					RewritePathPrefix:          route.RewritePathPrefix,
					GatewayEnabled:             route.Gateway != nil,
					GatewayRequired:            gatewayRequired,
					GatewayReplayAuthorization: gatewayReplayAuthorization,
					MockPreferExamples:         route.Mock != nil && route.Mock.PreferExamples,
				})
				if route.Mock != nil {
					item.Routes[len(item.Routes)-1].MockDefaultStatus = route.Mock.DefaultStatus
				}
			}
			response.Hosts = append(response.Hosts, item)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminReverseProxyLogs(w http.ResponseWriter, _ *http.Request) {
	response := adminReverseProxyLogsResponse{}
	if s.reverseProxyLog != nil {
		response.Entries = s.reverseProxyLog.Snapshot()
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminReverseProxyLogDetail(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimPrefix(r.URL.Path, "/console/api/reverse-proxy/logs/")
	if rawID == "" || rawID == "stream" || rawID == "replay" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid log id", http.StatusBadRequest)
		return
	}
	if s.reverseProxyLog == nil {
		http.NotFound(w, r)
		return
	}
	detail, ok := s.reverseProxyLog.Detail(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(detail); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminReverseProxyLogsReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read replay payload", http.StatusBadRequest)
		return
	}
	var requestItems []replayRequest
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&requestItems); err != nil {
		var single replayRequest
		singleDecoder := json.NewDecoder(bytes.NewReader(bodyBytes))
		singleDecoder.DisallowUnknownFields()
		if rewindErr := singleDecoder.Decode(&single); rewindErr != nil {
			http.Error(w, "invalid replay payload", http.StatusBadRequest)
			return
		}
		requestItems = []replayRequest{single}
	}
	s.replayLoggedRequests(requestItems, "Admin Console")
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleAdminReverseProxyLogsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	lastEventID := int64(0)
	if raw := strings.TrimSpace(r.Header.Get("Last-Event-ID")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			lastEventID = parsed
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	backlog := []reverseProxyLogSummary(nil)
	var updates <-chan reverseProxyLogSummary
	unsubscribe := func() {}
	if s.reverseProxyLog != nil {
		backlog, updates, unsubscribe = s.reverseProxyLog.SubscribeAfter(lastEventID)
	}
	defer unsubscribe()

	for _, entry := range backlog {
		if err := writeReverseProxyLogSSE(w, entry); err != nil {
			return
		}
		lastEventID = entry.ID
	}
	if err := writeSSEEvent(w, "sync", map[string]bool{"complete": true}, 0); err != nil {
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(adminReverseProxyLogsHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case entry := <-updates:
			if entry.ID <= lastEventID {
				continue
			}
			if err := writeReverseProxyLogSSE(w, entry); err != nil {
				return
			}
			lastEventID = entry.ID
		}
	}
}

func writeReverseProxyLogSSE(w http.ResponseWriter, entry reverseProxyLogSummary) error {
	return writeSSEEvent(w, "", entry, entry.ID)
}

func writeSSEEvent(w http.ResponseWriter, event string, payload any, eventID int64) error {
	if eventID > 0 {
		if _, err := fmt.Fprintf(w, "id: %d\n", eventID); err != nil {
			return err
		}
	}
	if event != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
			return err
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return nil
}

func cloneClaimsMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(src))
	maps.Copy(cloned, src)
	return cloned
}

func adminTLSSource(cfg *config.Config) string {
	if cfg == nil {
		return "none"
	}
	if !strings.HasPrefix(cfg.OIDC.Issuer, "https://") && (cfg.Autocert == nil || !cfg.Autocert.Enabled) {
		return "none"
	}
	if cfg.Autocert != nil && cfg.Autocert.Enabled {
		return "acme"
	}
	if strings.TrimSpace(cfg.OIDC.TLSCertFile) != "" || strings.TrimSpace(cfg.OIDC.TLSKeyFile) != "" {
		return "manual"
	}
	if cfg.CertificateAuthority != nil {
		return "self-signed"
	}
	return "manual"
}

func adminReverseProxyTLSSource(cfg *config.Config, host config.ReverseProxyHost) string {
	if host.Scheme() != "https" && !host.IsDefaultVirtualHost() {
		return "http"
	}
	if strings.TrimSpace(host.ResolvedTLSCertFile()) != "" {
		return "manual"
	}
	if cfg != nil && cfg.CertificateAuthority != nil {
		return "self-signed"
	}
	return "unknown"
}

func (s *Server) handleAdminCertificates(w http.ResponseWriter, _ *http.Request) {
	rootCA, _ := s.loadManagedRootCAInfo()
	leafCerts := []map[string]any{}
	if adminTLSSource(s.config) == "self-signed" {
		leafCerts, _ = s.loadManagedLeafCertificateInfos()
	}
	rootCAAvailable := rootCA != nil
	rootCAReason := "Managed root CA is not created until self-signed TLS runtime is integrated."
	if rootCAAvailable {
		rootCAReason = ""
	}

	response := map[string]any{
		"rootCA": map[string]any{
			"available": rootCAAvailable,
			"reason":    rootCAReason,
			"info":      rootCA,
		},
		"leafCertificates": leafCerts,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminIssueCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if s.config == nil || s.config.CertificateAuthority == nil {
		http.Error(w, ErrCertificateAuthorityConfigMissing.Error(), http.StatusBadRequest)
		return
	}
	if _, ok := firstManagedWildcardDomain(s.config.CertificateAuthority.Domains); !ok {
		http.Error(w, "managed wildcard domain is not configured", http.StatusBadRequest)
		return
	}

	var payload adminCertificateIssueRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	ttl, err := time.ParseDuration(strings.TrimSpace(payload.TTL))
	if err != nil || ttl <= 0 {
		http.Error(w, "ttl must be a valid positive duration", http.StatusBadRequest)
		return
	}
	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(payload.NotBefore))
	if err != nil {
		http.Error(w, "notBefore must be RFC3339", http.StatusBadRequest)
		return
	}
	host, err := managedWildcardHost(s.config.CertificateAuthority.Domains, payload.DomainLabel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bundle, err := ensureManagedSelfSignedTLSAssets(s.config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	caCert, caKey, caCertPEM, err := loadManagedCA(bundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	leaf, err := generateManagedLeafCertificateFromRequest(managedLeafCertificateRequest{
		Domain:       host,
		Organization: payload.Organization,
		NotBefore:    notBefore.UTC(),
		TTL:          ttl,
	}, caCert, caKey, caCertPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := persistManagedLeafCertificate(s.config, leaf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	archive, err := buildManagedLeafCertificateZip(leaf, leaf.certificate.NotBefore)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filename := strings.NewReplacer("*", "", "/", "-", "\\", "-", ":", "-").Replace(host)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "certificate-"+filename+".zip"))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(archive)))
	_, _ = w.Write(archive)
}

func (s *Server) handleAdminRootCADownload(w http.ResponseWriter, _ *http.Request) {
	bundle, err := ensureManagedSelfSignedTLSAssets(s.config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	caPEM, err := os.ReadFile(bundle.CACertPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="root-ca.pem"`)
	_, _ = w.Write(caPEM)
}

func (s *Server) handleAdminCertificateInstallerDownload(w http.ResponseWriter, _ *http.Request) {
	bundle, err := ensureManagedSelfSignedTLSAssets(s.config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	caPEM, err := os.ReadFile(bundle.CACertPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	caInfo, err := os.Stat(bundle.CACertPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	archive, err := buildCertificateInstallerZip(caPEM, caInfo.ModTime())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="certificate-installer.zip"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(archive)))
	_, _ = w.Write(archive)
}

func (s *Server) handleAdminUnixInstallScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="install.sh"`)
	_, _ = w.Write([]byte(generateUnixInstallScript()))
}

func (s *Server) handleAdminUnixUninstallScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="uninstall.sh"`)
	_, _ = w.Write([]byte(generateUnixUninstallScript()))
}

func (s *Server) handleAdminWindowsInstallScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="install.ps1"`)
	_, _ = w.Write([]byte(generateWindowsInstallScript()))
}

func (s *Server) handleAdminWindowsUninstallScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="uninstall.ps1"`)
	_, _ = w.Write([]byte(generateWindowsUninstallScript()))
}

func (s *Server) adminStaticHandler() http.Handler {
	if distFS, indexHTML, ok := s.findAdminDistFS(); ok {
		fileServer := http.FileServerFS(distFS)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trimmedPath := strings.TrimPrefix(r.URL.Path, "/console")
			if trimmedPath == "" || trimmedPath == "/" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(indexHTML)
				return
			}
			if strings.HasPrefix(trimmedPath, "/assets/") {
				req := r.Clone(r.Context())
				urlCopy := *r.URL
				urlCopy.Path = strings.TrimPrefix(trimmedPath, "/")
				urlCopy.RawPath = urlCopy.Path
				req.URL = &urlCopy
				fileServer.ServeHTTP(w, req)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexHTML)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>OIDCLD Developer Console</h1><p>Developer console assets were not found. Build web/admin with npm run build.</p></body></html>`))
	})
}

func isConsolePath(path string) bool {
	return path == "/console" || path == "/console/" || strings.HasPrefix(path, "/console/")
}

func (s *Server) shouldServeConsoleMetadata(path string) bool {
	if !strings.HasPrefix(s.config.OIDC.Issuer, "https://") {
		return false
	}
	_, ok := s.readOnlyHTTPCanonicalPath(path)
	return ok
}

func (s *Server) findAdminDistFS() (fs.FS, []byte, bool) {
	if embeddedFS, indexHTML, ok := adminassets.Open(); ok {
		return embeddedFS, indexHTML, true
	}

	for _, candidate := range adminDistCandidates(s.config.SourceDir()) {
		indexPath := filepath.Join(candidate, "index.html")
		indexHTML, err := os.ReadFile(indexPath)
		if err != nil {
			continue
		}
		return os.DirFS(candidate), indexHTML, true
	}
	return nil, nil, false
}

func adminDistCandidates(sourceDir string) []string {
	seen := map[string]struct{}{}
	var candidates []string
	appendCandidate := func(path string) {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			return
		}
		cleaned := filepath.Clean(trimmed)
		if _, ok := seen[cleaned]; ok {
			return
		}
		seen[cleaned] = struct{}{}
		candidates = append(candidates, cleaned)
	}

	if sourceDir != "" {
		appendCandidate(filepath.Join(sourceDir, "web", "admin", "dist"))
		appendCandidate(filepath.Join(sourceDir, "internal", "server", "adminassets", "generated"))
	}
	if wd, err := os.Getwd(); err == nil {
		appendCandidate(filepath.Join(wd, "web", "admin", "dist"))
		appendCandidate(filepath.Join(wd, "internal", "server", "adminassets", "generated"))
		appendCandidate(filepath.Join(wd, "..", "web", "admin", "dist"))
		appendCandidate(filepath.Join(wd, "..", "internal", "server", "adminassets", "generated"))
		appendCandidate(filepath.Join(wd, "..", "..", "web", "admin", "dist"))
		appendCandidate(filepath.Join(wd, "..", "..", "internal", "server", "adminassets", "generated"))
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		appendCandidate(filepath.Join(exeDir, "web", "admin", "dist"))
		appendCandidate(filepath.Join(exeDir, "internal", "server", "adminassets", "generated"))
		appendCandidate(filepath.Join(exeDir, "..", "web", "admin", "dist"))
		appendCandidate(filepath.Join(exeDir, "..", "internal", "server", "adminassets", "generated"))
		appendCandidate(filepath.Join(exeDir, "..", "..", "web", "admin", "dist"))
		appendCandidate(filepath.Join(exeDir, "..", "..", "internal", "server", "adminassets", "generated"))
	}
	if _, currentFile, _, ok := runtime.Caller(0); ok {
		appendCandidate(filepath.Join(filepath.Dir(currentFile), "..", "..", "web", "admin", "dist"))
		appendCandidate(filepath.Join(filepath.Dir(currentFile), "adminassets", "generated"))
	}
	return candidates
}

func (s *Server) adminLocalOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bindAddress := "127.0.0.1"
		if s != nil && s.config.Console != nil && strings.TrimSpace(s.config.Console.BindAddress) != "" {
			bindAddress = strings.TrimSpace(s.config.Console.BindAddress)
		}
		if !consoleRequiresLoopbackClient(bindAddress) {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			writeDiagnosticError(w, r, http.StatusForbidden, "admin_local_only_peer_not_allowed", "peer_not_allowed", "The Developer Console is restricted to loopback clients because console.bind_address is configured for local-only access.", map[string]any{
				"remote_addr":   r.RemoteAddr,
				"console_bind":  bindAddress,
				"loopback_only": true,
			}, "Bind the console to 0.0.0.0 or :: if you intentionally want remote clients to access it.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func consoleRequiresLoopbackClient(bindAddress string) bool {
	switch bindAddress {
	case "0.0.0.0", "::", "[::]":
		return false
	}

	ip := net.ParseIP(strings.Trim(bindAddress, "[]"))
	if ip == nil {
		return true
	}
	return ip.IsLoopback()
}

//nolint:dupword // Embedded shell script intentionally repeats shell keywords like fi.
func generateUnixInstallScript() string {
	return `#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CA_FILE="${SCRIPT_DIR}/root-ca.pem"
JAVA_DER_FILE="${SCRIPT_DIR}/root-ca.der"
CA_ALIAS="oidcld-development-root-ca"

if [ ! -f "$CA_FILE" ]; then
	echo "root-ca.pem not found next to this script" >&2
	exit 1
fi

resolve_user_keychain() {
	KEYCHAIN_PATH="$(security default-keychain -d user 2>/dev/null | tr -d '"' | xargs || true)"
	if [ -n "$KEYCHAIN_PATH" ] && [ -e "$KEYCHAIN_PATH" ]; then
		printf '%s\n' "$KEYCHAIN_PATH"
		return 0
	fi

	for CANDIDATE in \
		"$HOME/Library/Keychains/login.keychain-db" \
		"$HOME/Library/Keychains/login.keychain"; do
		if [ -e "$CANDIDATE" ]; then
			printf '%s\n' "$CANDIDATE"
			return 0
		fi
	done

	return 1
}

install_java() {
	KEYTOOL=""

	if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/keytool" ]; then
		KEYTOOL="${JAVA_HOME}/bin/keytool"
	elif command -v keytool >/dev/null 2>&1; then
		KEYTOOL="keytool"
	elif [ -x "$HOME/.sdkman/candidates/java/current/bin/keytool" ]; then
		KEYTOOL="$HOME/.sdkman/candidates/java/current/bin/keytool"
	elif [ "$(uname -s)" = "Darwin" ] && [ -x "/usr/libexec/java_home" ]; then
		JAVA_HOME_RESOLVED=$(/usr/libexec/java_home 2>/dev/null || true)
		if [ -n "$JAVA_HOME_RESOLVED" ] && [ -x "${JAVA_HOME_RESOLVED}/bin/keytool" ]; then
			KEYTOOL="${JAVA_HOME_RESOLVED}/bin/keytool"
		fi
	fi

	if [ -z "$KEYTOOL" ]; then
		echo "Java keytool not found, skipping Java trust store installation"
		return
	fi

	if ! openssl x509 -outform der -in "$CA_FILE" -out "$JAVA_DER_FILE" >/dev/null 2>&1; then
		echo "Failed to convert root-ca.pem to DER format for Java" >&2
		return
	fi

	for CANDIDATE in \
		"${JAVA_HOME:-}/lib/security/cacerts" \
		"${JAVA_HOME:-}/jre/lib/security/cacerts" \
		"$HOME/.sdkman/candidates/java/current/lib/security/cacerts" \
		"$HOME/.sdkman/candidates/java/"*/lib/security/cacerts \
		"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts" \
		"/opt/homebrew/opt/openjdk"*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts \
		"/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts" \
		"/usr/local/opt/openjdk"*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts \
		"/etc/ssl/certs/java/cacerts" \
		"/usr/lib/jvm/default-java/lib/security/cacerts" \
		"/usr/lib/jvm/"*/lib/security/cacerts \
		"/System/Library/Java/Support/CoreDeploy.bundle/Contents/Home/lib/security/cacerts" \
		"/Library/Java/JavaVirtualMachines/"*/Contents/Home/lib/security/cacerts; do
		if [ ! -f "$CANDIDATE" ]; then
			continue
		fi

		if "$KEYTOOL" -list -alias "$CA_ALIAS" -keystore "$CANDIDATE" -storepass changeit -noprompt >/dev/null 2>&1; then
			echo "Java trust store already contains OIDCLD root CA: $CANDIDATE"
			return
		fi

		if [ -w "$CANDIDATE" ]; then
			if "$KEYTOOL" -importcert -file "$JAVA_DER_FILE" -alias "$CA_ALIAS" -keystore "$CANDIDATE" -storepass changeit -noprompt >/dev/null 2>&1; then
				echo "OIDCLD root CA installed to Java trust store: $CANDIDATE"
				return
			fi
		elif command -v sudo >/dev/null 2>&1; then
			if sudo "$KEYTOOL" -importcert -file "$JAVA_DER_FILE" -alias "$CA_ALIAS" -keystore "$CANDIDATE" -storepass changeit -noprompt >/dev/null 2>&1; then
				echo "OIDCLD root CA installed to Java trust store: $CANDIDATE"
				return
			fi
		fi
	done

	echo "No writable Java trust store found, skipping Java installation"
}

install_nss() {
	if ! command -v certutil >/dev/null 2>&1; then
		echo "certutil not found, skipping Firefox/NSS trust store installation"
		return
	fi

	INSTALLED=false
	for NSS_DIR in \
		"$HOME/.pki/nssdb" \
		"$HOME/.mozilla/firefox/"*/. \
		"$HOME/snap/firefox/common/.mozilla/firefox/"*/. \
		"/etc/pki/nssdb"; do
		if [ ! -d "$NSS_DIR" ]; then
			continue
		fi
		if [ ! -f "$NSS_DIR/cert9.db" ] && [ ! -f "$NSS_DIR/cert8.db" ]; then
			continue
		fi

		if certutil -L -n "OIDCLD Development Root CA" -d "$NSS_DIR" >/dev/null 2>&1; then
			echo "Firefox/NSS trust store already contains OIDCLD root CA: $NSS_DIR"
			INSTALLED=true
			continue
		fi

		if certutil -A -n "OIDCLD Development Root CA" -t "C,," -i "$CA_FILE" -d "$NSS_DIR" >/dev/null 2>&1; then
			echo "OIDCLD root CA installed to Firefox/NSS trust store: $NSS_DIR"
			INSTALLED=true
		fi
	done

	if [ "$INSTALLED" = false ]; then
		echo "No Firefox/NSS trust store found, skipping NSS installation"
	fi
}

if [ "$(uname -s)" = "Darwin" ]; then
	KEYCHAIN_PATH="$(resolve_user_keychain || true)"
	if [ -z "$KEYCHAIN_PATH" ]; then
		echo "Failed to resolve the default login keychain" >&2
		exit 1
	fi
	security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN_PATH" "$CA_FILE"
fi

if command -v update-ca-certificates >/dev/null 2>&1; then
	sudo cp "$CA_FILE" /usr/local/share/ca-certificates/oidcld-root-ca.crt
	sudo update-ca-certificates
fi

if command -v update-ca-trust >/dev/null 2>&1; then
	sudo cp "$CA_FILE" /etc/pki/ca-trust/source/anchors/oidcld-root-ca.crt
	sudo update-ca-trust
fi

install_java
install_nss

rm -f "$JAVA_DER_FILE"
`
}

//nolint:dupword // Embedded shell script intentionally repeats shell keywords like fi.
func generateUnixUninstallScript() string {
	return `#!/bin/sh
set -eu

CA_ALIAS="oidcld-development-root-ca"

resolve_user_keychain() {
	KEYCHAIN_PATH="$(security default-keychain -d user 2>/dev/null | tr -d '"' | xargs || true)"
	if [ -n "$KEYCHAIN_PATH" ] && [ -e "$KEYCHAIN_PATH" ]; then
		printf '%s\n' "$KEYCHAIN_PATH"
		return 0
	fi

	for CANDIDATE in \
		"$HOME/Library/Keychains/login.keychain-db" \
		"$HOME/Library/Keychains/login.keychain"; do
		if [ -e "$CANDIDATE" ]; then
			printf '%s\n' "$CANDIDATE"
			return 0
		fi
	done

	return 1
}

uninstall_java() {
	KEYTOOL=""

	if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/keytool" ]; then
		KEYTOOL="${JAVA_HOME}/bin/keytool"
	elif command -v keytool >/dev/null 2>&1; then
		KEYTOOL="keytool"
	elif [ -x "$HOME/.sdkman/candidates/java/current/bin/keytool" ]; then
		KEYTOOL="$HOME/.sdkman/candidates/java/current/bin/keytool"
	elif [ "$(uname -s)" = "Darwin" ] && [ -x "/usr/libexec/java_home" ]; then
		JAVA_HOME_RESOLVED=$(/usr/libexec/java_home 2>/dev/null || true)
		if [ -n "$JAVA_HOME_RESOLVED" ] && [ -x "${JAVA_HOME_RESOLVED}/bin/keytool" ]; then
			KEYTOOL="${JAVA_HOME_RESOLVED}/bin/keytool"
		fi
	fi

	if [ -z "$KEYTOOL" ]; then
		echo "Java keytool not found, skipping Java trust store removal"
		return
	fi

	for CANDIDATE in \
		"${JAVA_HOME:-}/lib/security/cacerts" \
		"${JAVA_HOME:-}/jre/lib/security/cacerts" \
		"$HOME/.sdkman/candidates/java/current/lib/security/cacerts" \
		"$HOME/.sdkman/candidates/java/"*/lib/security/cacerts \
		"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts" \
		"/opt/homebrew/opt/openjdk"*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts \
		"/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts" \
		"/usr/local/opt/openjdk"*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts \
		"/etc/ssl/certs/java/cacerts" \
		"/usr/lib/jvm/default-java/lib/security/cacerts" \
		"/usr/lib/jvm/"*/lib/security/cacerts \
		"/System/Library/Java/Support/CoreDeploy.bundle/Contents/Home/lib/security/cacerts" \
		"/Library/Java/JavaVirtualMachines/"*/Contents/Home/lib/security/cacerts; do
		if [ ! -f "$CANDIDATE" ]; then
			continue
		fi

		if [ -w "$CANDIDATE" ]; then
			"$KEYTOOL" -delete -alias "$CA_ALIAS" -keystore "$CANDIDATE" -storepass changeit -noprompt >/dev/null 2>&1 || true
		elif command -v sudo >/dev/null 2>&1; then
			sudo "$KEYTOOL" -delete -alias "$CA_ALIAS" -keystore "$CANDIDATE" -storepass changeit -noprompt >/dev/null 2>&1 || true
		fi
	done
}

uninstall_nss() {
	if ! command -v certutil >/dev/null 2>&1; then
		echo "certutil not found, skipping Firefox/NSS trust store removal"
		return
	fi

	for NSS_DIR in \
		"$HOME/.pki/nssdb" \
		"$HOME/.mozilla/firefox/"*/. \
		"$HOME/snap/firefox/common/.mozilla/firefox/"*/. \
		"/etc/pki/nssdb"; do
		if [ ! -d "$NSS_DIR" ]; then
			continue
		fi
		if [ ! -f "$NSS_DIR/cert9.db" ] && [ ! -f "$NSS_DIR/cert8.db" ]; then
			continue
		fi
		certutil -D -n "OIDCLD Development Root CA" -d "$NSS_DIR" >/dev/null 2>&1 || true
	done
}

if [ "$(uname -s)" = "Darwin" ]; then
	KEYCHAIN_PATH="$(resolve_user_keychain || true)"
	if [ -z "$KEYCHAIN_PATH" ]; then
		echo "Failed to resolve the default login keychain" >&2
		exit 1
	fi
	CERT_HASH="$(security find-certificate -c "OIDCLD Development Root CA" -Z "$KEYCHAIN_PATH" 2>/dev/null | awk '/SHA-1 hash:/ { print $3; exit }')"
	if [ -n "$CERT_HASH" ]; then
		security delete-certificate -Z "$CERT_HASH" "$KEYCHAIN_PATH"
	fi
fi

if command -v update-ca-certificates >/dev/null 2>&1; then
	sudo rm -f /usr/local/share/ca-certificates/oidcld-root-ca.crt
	sudo update-ca-certificates
fi

if command -v update-ca-trust >/dev/null 2>&1; then
	sudo rm -f /etc/pki/ca-trust/source/anchors/oidcld-root-ca.crt
	sudo update-ca-trust
fi

uninstall_java
uninstall_nss
`
}

func generateWindowsInstallScript() string {
	return `$ErrorActionPreference = "Stop"
$javaAlias = "oidcld-development-root-ca"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$certPath = Join-Path $scriptDir "root-ca.pem"
if (-not (Test-Path $certPath)) {
	throw "root-ca.pem not found next to this script"
}
Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

$keytool = $null
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME "bin\keytool.exe"))) {
	$keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"
} else {
	$keytoolCommand = Get-Command keytool.exe -ErrorAction SilentlyContinue
	if ($keytoolCommand) {
		$keytool = $keytoolCommand.Source
	}
}

if ($keytool) {
	$derPath = Join-Path $scriptDir "root-ca.der"
	try {
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
		[System.IO.File]::WriteAllBytes($derPath, $cert.RawData)
		$cacertsCandidates = @()
		if ($env:JAVA_HOME) {
			$cacertsCandidates += (Join-Path $env:JAVA_HOME "lib\security\cacerts")
			$cacertsCandidates += (Join-Path $env:JAVA_HOME "jre\lib\security\cacerts")
		}
		$cacertsCandidates += Get-ChildItem "C:\Program Files\Java\*\lib\security\cacerts" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
		$cacertsCandidates += Get-ChildItem "C:\Program Files\Eclipse Adoptium\*\lib\security\cacerts" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
		foreach ($cacerts in $cacertsCandidates | Select-Object -Unique) {
			if (-not (Test-Path $cacerts)) {
				continue
			}
			& $keytool -list -alias $javaAlias -keystore $cacerts -storepass changeit -noprompt *> $null
			if ($LASTEXITCODE -eq 0) {
				Write-Host "OIDCLD root CA already exists in Java trust store: $cacerts"
				break
			}
			& $keytool -importcert -file $derPath -alias $javaAlias -keystore $cacerts -storepass changeit -noprompt *> $null
			if ($LASTEXITCODE -eq 0) {
				Write-Host "OIDCLD root CA installed to Java trust store: $cacerts"
				break
			}
		}
	} finally {
		if (Test-Path $derPath) {
			Remove-Item $derPath -Force
		}
	}
} else {
	Write-Host "Java keytool not found, skipping Java trust store installation"
}
Write-Host "OIDCLD root CA installed"
`
}

func generateWindowsUninstallScript() string {
	return `$ErrorActionPreference = "Stop"
$javaAlias = "oidcld-development-root-ca"
$certs = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*OIDCLD Development Root CA*" }
foreach ($cert in $certs) {
	Remove-Item -Path $cert.PSPath
}

$keytool = $null
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME "bin\keytool.exe"))) {
	$keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"
} else {
	$keytoolCommand = Get-Command keytool.exe -ErrorAction SilentlyContinue
	if ($keytoolCommand) {
		$keytool = $keytoolCommand.Source
	}
}

if ($keytool) {
	$cacertsCandidates = @()
	if ($env:JAVA_HOME) {
		$cacertsCandidates += (Join-Path $env:JAVA_HOME "lib\security\cacerts")
		$cacertsCandidates += (Join-Path $env:JAVA_HOME "jre\lib\security\cacerts")
	}
	$cacertsCandidates += Get-ChildItem "C:\Program Files\Java\*\lib\security\cacerts" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
	$cacertsCandidates += Get-ChildItem "C:\Program Files\Eclipse Adoptium\*\lib\security\cacerts" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
	foreach ($cacerts in $cacertsCandidates | Select-Object -Unique) {
		if (-not (Test-Path $cacerts)) {
			continue
		}
		& $keytool -delete -alias $javaAlias -keystore $cacerts -storepass changeit -noprompt *> $null
	}
} else {
	Write-Host "Java keytool not found, skipping Java trust store removal"
}
Write-Host "OIDCLD root CA removed"
`
}

func buildCertificateInstallerZip(caPEM []byte, modifiedAt time.Time) ([]byte, error) {
	files := []struct {
		name    string
		content []byte
		mode    fs.FileMode
	}{
		{name: "root-ca.pem", content: caPEM, mode: 0644},
		{name: "install.sh", content: []byte(generateUnixInstallScript()), mode: 0755},
		{name: "install.ps1", content: []byte(generateWindowsInstallScript()), mode: 0644},
		{name: "uninstall.sh", content: []byte(generateUnixUninstallScript()), mode: 0755},
		{name: "uninstall.ps1", content: []byte(generateWindowsUninstallScript()), mode: 0644},
	}

	return buildZipArchive(files, modifiedAt)
}

func buildManagedLeafCertificateZip(leaf *managedLeafCertificate, modifiedAt time.Time) ([]byte, error) {
	files := []struct {
		name    string
		content []byte
		mode    fs.FileMode
	}{
		{name: "certificate.pem", content: leaf.certPEM, mode: 0644},
		{name: "private-key.pem", content: leaf.keyPEM, mode: 0600},
	}
	return buildZipArchive(files, modifiedAt)
}

func buildZipArchive(files []struct {
	name    string
	content []byte
	mode    fs.FileMode
}, modifiedAt time.Time) ([]byte, error) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, file := range files {
		header := &zip.FileHeader{
			Name:     file.name,
			Method:   zip.Deflate,
			Modified: modifiedAt,
		}
		header.SetMode(file.mode)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			_ = archive.Close()
			return nil, err
		}
		if _, err := writer.Write(file.content); err != nil {
			_ = archive.Close()
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
