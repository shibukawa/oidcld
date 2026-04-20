package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	neturl "net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	maxCapturedRequestBodyBytes  = 64 * 1024
	maxCapturedResponseBodyBytes = 64 * 1024
)

var (
	ErrReplayTargetInvalid          = errors.New("invalid replay target")
	ErrReplayRequestFieldsRequired  = errors.New("scheme, host, and path are required")
)

type reverseProxyLogSummary struct {
	ID               int64     `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	Host             string    `json:"host"`
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	StatusCode       int       `json:"statusCode"`
	ContentTypeLabel string    `json:"contentTypeLabel"`
	DurationMS       int64     `json:"durationMs"`
	Bytes            int       `json:"bytes"`
	RouteType        string    `json:"routeType"`
	RouteHost        string    `json:"routeHost"`
	RoutePath        string    `json:"routePath"`
	RouteLabel       string    `json:"routeLabel"`
}

type capturedBody struct {
	Kind          string `json:"kind"`
	ContentType   string `json:"contentType,omitempty"`
	Text          string `json:"text,omitempty"`
	Truncated     bool   `json:"truncated,omitempty"`
	OmittedReason string `json:"omittedReason,omitempty"`
}

type capturedRequest struct {
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers"`
	Body    capturedBody        `json:"body"`
}

type capturedResponse struct {
	StatusCode  int                 `json:"statusCode"`
	Headers     map[string][]string `json:"headers"`
	ContentType string              `json:"contentType,omitempty"`
	Bytes       int                 `json:"bytes"`
	Body        capturedBody        `json:"body"`
}

type reverseProxyLogDetail struct {
	ID         int64                  `json:"id"`
	Summary    reverseProxyLogSummary `json:"summary"`
	Target     string                 `json:"target"`
	RewritePathPrefix string          `json:"rewritePathPrefix,omitempty"`
	RemoteAddr string                 `json:"remoteAddr"`
	Request    capturedRequest        `json:"request"`
	Response   capturedResponse       `json:"response"`
}

type reverseProxyLogRecord struct {
	summary reverseProxyLogSummary
	detail  reverseProxyLogDetail
}

type reverseProxyLogMeta struct {
	RouteType         string
	RouteHost         string
	RoutePath         string
	RouteLabel        string
	Target            string
	RewritePathPrefix string
}

type reverseProxyLogStore struct {
	mu               sync.RWMutex
	entries          []reverseProxyLogRecord
	limit            int
	nextID           int64
	nextSubscriberID int
	subscribers      map[int]chan reverseProxyLogSummary
}

type replayRequest struct {
	Name              string              `json:"name,omitempty"`
	Scheme            string              `json:"scheme"`
	Host              string              `json:"host"`
	Method            string              `json:"method"`
	Path              string              `json:"path"`
	Query             string              `json:"query,omitempty"`
	Headers           map[string][]string `json:"headers,omitempty"`
	Body              capturedBody        `json:"body"`
	RouteType         string              `json:"routeType,omitempty"`
	RouteHost         string              `json:"routeHost,omitempty"`
	RoutePath         string              `json:"routePath,omitempty"`
	RouteLabel        string              `json:"routeLabel,omitempty"`
	Target            string              `json:"target,omitempty"`
	RewritePathPrefix string              `json:"rewritePathPrefix,omitempty"`
}

func newReverseProxyLogStore(limit int) *reverseProxyLogStore {
	if limit <= 0 {
		limit = 200
	}
	return &reverseProxyLogStore{
		limit:       limit,
		subscribers: map[int]chan reverseProxyLogSummary{},
	}
}

func (s *reverseProxyLogStore) Add(summary reverseProxyLogSummary, detail reverseProxyLogDetail) int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	s.nextID++
	summary.ID = s.nextID
	detail.ID = s.nextID
	detail.Summary = summary
	record := reverseProxyLogRecord{summary: summary, detail: detail}
	s.entries = append(s.entries, record)
	if extra := len(s.entries) - s.limit; extra > 0 {
		s.entries = append([]reverseProxyLogRecord(nil), s.entries[extra:]...)
	}
	subscribers := make([]chan reverseProxyLogSummary, 0, len(s.subscribers))
	for _, subscriber := range s.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	s.mu.Unlock()

	for _, subscriber := range subscribers {
		select {
		case subscriber <- summary:
		default:
		}
	}
	return summary.ID
}

func (s *reverseProxyLogStore) Snapshot() []reverseProxyLogSummary {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]reverseProxyLogSummary, 0, len(s.entries))
	for _, entry := range s.entries {
		out = append(out, entry.summary)
	}
	slices.Reverse(out)
	return out
}

func (s *reverseProxyLogStore) Detail(id int64) (reverseProxyLogDetail, bool) {
	if s == nil {
		return reverseProxyLogDetail{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.entries {
		if entry.summary.ID == id {
			return entry.detail, true
		}
	}
	return reverseProxyLogDetail{}, false
}

func (s *reverseProxyLogStore) SubscribeAfter(lastID int64) ([]reverseProxyLogSummary, <-chan reverseProxyLogSummary, func()) {
	if s == nil {
		return nil, nil, func() {}
	}

	s.mu.Lock()
	backlog := s.entriesAfterLocked(lastID)
	subscriberID := s.nextSubscriberID
	s.nextSubscriberID++
	ch := make(chan reverseProxyLogSummary, 32)
	s.subscribers[subscriberID] = ch
	s.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subscribers, subscriberID)
			s.mu.Unlock()
		})
	}

	return backlog, ch, unsubscribe
}

func (s *reverseProxyLogStore) entriesAfterLocked(lastID int64) []reverseProxyLogSummary {
	start := 0
	for start < len(s.entries) && s.entries[start].summary.ID <= lastID {
		start++
	}
	out := make([]reverseProxyLogSummary, 0, len(s.entries)-start)
	for _, entry := range s.entries[start:] {
		out = append(out, entry.summary)
	}
	return out
}

func contentTypeLabel(raw string) string {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
	}
	switch mediaType {
	case "", "application/octet-stream":
		return "-"
	case "application/json", "application/problem+json":
		return "JSON"
	case "text/html":
		return "HTML"
	case "text/css":
		return "CSS"
	case "text/javascript", "application/javascript", "application/x-javascript":
		return "JS"
	case "text/plain":
		return "Text"
	case "application/xml", "text/xml":
		return "XML"
	case "text/csv":
		return "CSV"
	}
	if strings.HasPrefix(mediaType, "image/") {
		return "Image"
	}
	if strings.HasPrefix(mediaType, "text/") {
		return "Text"
	}
	if strings.HasSuffix(mediaType, "+json") {
		return "JSON"
	}
	return "Other"
}

func cloneHeaderMap(header http.Header) map[string][]string {
	if len(header) == 0 {
		return map[string][]string{}
	}
	cloned := make(map[string][]string, len(header))
	for key, values := range header {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func bodyKindFromContentType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return "json"
	case mediaType == "application/x-www-form-urlencoded":
		return "form"
	case strings.HasPrefix(mediaType, "text/"):
		return "text"
	case strings.HasPrefix(mediaType, "image/"):
		return "binary"
	case strings.HasPrefix(mediaType, "multipart/"):
		return "multipart"
	case mediaType == "":
		return ""
	default:
		return "binary"
	}
}

func captureRequestForLog(r *http.Request) capturedRequest {
	request := capturedRequest{
		Method:  r.Method,
		Headers: cloneHeaderMap(r.Header),
		Body:    capturedBody{Kind: "none"},
	}
	if r.URL != nil {
		request.Path = r.URL.Path
		request.Query = r.URL.RawQuery
	}
	request.Host = strings.TrimSpace(r.Host)
	request.Scheme = forwardedScheme(r)
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	request.Body.ContentType = contentType
	request.Body.Kind = bodyKindFromContentType(contentType)

	switch request.Body.Kind {
	case "", "none":
		request.Body.Kind = "none"
		return request
	case "multipart", "binary":
		request.Body.OmittedReason = "unsupported"
		return request
	}
	if r.Body == nil {
		return request
	}
	if r.ContentLength > maxCapturedRequestBodyBytes {
		request.Body.Truncated = true
		request.Body.OmittedReason = "too_large"
		return request
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		request.Body.OmittedReason = "read_error"
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return request
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if len(bodyBytes) > maxCapturedRequestBodyBytes {
		request.Body.Truncated = true
		request.Body.Text = string(bodyBytes[:maxCapturedRequestBodyBytes])
		return request
	}
	request.Body.Text = string(bodyBytes)
	return request
}

func captureResponseBody(contentType string, body []byte, limit int) capturedBody {
	result := capturedBody{
		Kind:        bodyKindFromContentType(contentType),
		ContentType: strings.TrimSpace(contentType),
	}
	switch result.Kind {
	case "", "none":
		result.Kind = "none"
		return result
	case "multipart", "binary":
		result.OmittedReason = "unsupported"
		return result
	}
	if len(body) == 0 {
		return result
	}
	if len(body) > limit {
		result.Truncated = true
		body = body[:limit]
	}
	result.Text = string(body)
	return result
}

func matchLogPathPattern(pattern, requestPath string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	ok, err := filepath.Match(pattern, requestPath)
	return err == nil && ok
}

func (s *Server) shouldIgnoreAccessLog(path string) bool {
	if s == nil || s.config == nil || s.config.ReverseProxy == nil {
		return path == "/health"
	}
	for _, pattern := range s.config.ReverseProxy.IgnoreLogPaths {
		if matchLogPathPattern(pattern, path) {
			return true
		}
	}
	return false
}

func (s *Server) replayLoggedRequests(items []replayRequest, remoteAddr string) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, item := range items {
		start := time.Now()
		item = s.resolveReplayRequest(item)
		requestCapture := capturedRequest{
			Scheme:  item.Scheme,
			Host:    item.Host,
			Method:  item.Method,
			Path:    item.Path,
			Query:   item.Query,
			Headers: cloneHeaderMap(http.Header(item.Headers)),
			Body:    item.Body,
		}
		if requestCapture.Headers == nil {
			requestCapture.Headers = map[string][]string{}
		}
		req, err := buildReplayHTTPRequest(item)
		if err != nil {
			s.recordReplayLog(item, remoteAddr, requestCapture, capturedResponse{
				StatusCode:  http.StatusBadGateway,
				Headers:     map[string][]string{},
				ContentType: "text/plain",
				Bytes:       len(err.Error()),
				Body: capturedBody{
					Kind:        "text",
					ContentType: "text/plain",
					Text:        err.Error(),
				},
			}, time.Since(start))
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			s.recordReplayLog(item, remoteAddr, requestCapture, capturedResponse{
				StatusCode:  http.StatusBadGateway,
				Headers:     map[string][]string{},
				ContentType: "text/plain",
				Bytes:       len(err.Error()),
				Body: capturedBody{
					Kind:        "text",
					ContentType: "text/plain",
					Text:        err.Error(),
				},
			}, time.Since(start))
			continue
		}
		responseBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxCapturedResponseBodyBytes+1))
		_ = resp.Body.Close()
		responseContentType := resp.Header.Get("Content-Type")
		s.recordReplayLog(item, remoteAddr, requestCapture, capturedResponse{
			StatusCode:  resp.StatusCode,
			Headers:     cloneHeaderMap(resp.Header),
			ContentType: responseContentType,
			Bytes:       len(responseBytes),
			Body:        captureResponseBody(responseContentType, responseBytes, maxCapturedResponseBodyBytes),
		}, time.Since(start))
	}
}

func (s *Server) recordReplayLog(item replayRequest, remoteAddr string, request capturedRequest, response capturedResponse, duration time.Duration) {
	if s == nil || s.reverseProxyLog == nil {
		return
	}
	if request.Method == "" {
		request.Method = http.MethodGet
	}
	if request.Path == "" {
		request.Path = "/"
	}
	if request.Headers == nil {
		request.Headers = map[string][]string{}
	}
	if remoteAddr == "" {
		remoteAddr = "Admin Console"
	}
	displayPath := request.Path
	if !strings.HasPrefix(displayPath, "(REPLAY) ") {
		displayPath = "(REPLAY) " + displayPath
	}
	summary := reverseProxyLogSummary{
		Timestamp:        time.Now().UTC(),
		Host:             request.Host,
		Method:           request.Method,
		Path:             displayPath,
		StatusCode:       response.StatusCode,
		ContentTypeLabel: contentTypeLabel(response.ContentType),
		DurationMS:       duration.Milliseconds(),
		Bytes:            response.Bytes,
		RouteType:        item.RouteType,
		RouteHost:        item.RouteHost,
		RoutePath:        item.RoutePath,
		RouteLabel:       item.RouteLabel,
	}
	detail := reverseProxyLogDetail{
		Target:            item.Target,
		RewritePathPrefix: item.RewritePathPrefix,
		RemoteAddr:        remoteAddr,
		Request:           request,
		Response:          response,
	}
	s.reverseProxyLog.Add(summary, detail)
}

func (s *Server) resolveReplayRequest(item replayRequest) replayRequest {
	if s == nil {
		return item
	}
	if strings.TrimSpace(item.Path) == "" {
		item.Path = "/"
	}
	req := &http.Request{
		Host: item.Host,
		URL: &neturl.URL{
			Path: item.Path,
		},
	}
	if strings.EqualFold(strings.TrimSpace(item.Scheme), "https") {
		req.TLS = &tls.ConnectionState{}
	}
	if s.reverseProxy != nil {
		if match, ok := s.reverseProxy.match(req); ok {
			item.RouteType = match.route.routeType
			item.RouteHost = match.host.displayHost
			item.RoutePath = match.route.path
			item.RouteLabel = match.route.label
			item.Target = match.route.targetLabel
			item.RewritePathPrefix = match.route.rewritePathPrefix
			return item
		}
	}
	if logMeta := s.oidcTrafficLogMeta(req); logMeta != nil {
		item.RouteType = logMeta.RouteType
		item.RouteHost = logMeta.RouteHost
		item.RoutePath = logMeta.RoutePath
		item.RouteLabel = logMeta.RouteLabel
		item.Target = logMeta.Target
	}
	return item
}

func buildReplayHTTPRequest(item replayRequest) (*http.Request, error) {
	method := strings.TrimSpace(item.Method)
	if method == "" {
		method = http.MethodGet
	}
	path := strings.TrimSpace(item.Path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var target *neturl.URL
	if item.RouteType == "proxy" && strings.TrimSpace(item.Target) != "" {
		parsedTarget, err := neturl.Parse(strings.TrimSpace(item.Target))
		if err != nil || parsedTarget.Scheme == "" || parsedTarget.Host == "" {
			return nil, ErrReplayTargetInvalid
		}
		rewrittenPath := rewriteMatchedPath(path, item.RoutePath, item.RewritePathPrefix)
		target = &neturl.URL{
			Scheme:   parsedTarget.Scheme,
			Host:     parsedTarget.Host,
			Path:     singleJoiningSlash(parsedTarget.Path, rewrittenPath),
			RawQuery: item.Query,
		}
	} else {
		scheme := strings.TrimSpace(item.Scheme)
		host := strings.TrimSpace(item.Host)
		if scheme == "" || host == "" || path == "" {
			return nil, ErrReplayRequestFieldsRequired
		}
		target = &neturl.URL{
			Scheme:   scheme,
			Host:     host,
			Path:     path,
			RawQuery: item.Query,
		}
	}
	bodyText := item.Body.Text
	if item.Body.Kind == "none" || item.Body.OmittedReason != "" {
		bodyText = ""
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target.String(), strings.NewReader(bodyText))
	if err != nil {
		return nil, err
	}
	for key, values := range item.Headers {
		canonical := http.CanonicalHeaderKey(key)
		switch canonical {
		case "Host", "Content-Length", "Connection", "Accept-Encoding", "Cookie":
			continue
		}
		for _, value := range values {
			req.Header.Add(canonical, value)
		}
	}
	if item.Body.ContentType != "" && req.Header.Get("Content-Type") == "" && bodyText != "" {
		req.Header.Set("Content-Type", item.Body.ContentType)
	}
	return req, nil
}

func trimCapturedResponseBytes(buf []byte, truncated bool) []byte {
	if truncated && len(buf) > maxCapturedResponseBodyBytes {
		return append([]byte(nil), buf[:maxCapturedResponseBodyBytes]...)
	}
	return append([]byte(nil), buf...)
}
