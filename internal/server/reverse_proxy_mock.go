package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/shibukawa/oidcld/internal/config"
)

var (
	errOpenAPIMockOperationNotFound = errors.New("openapi mock operation not found")
	errOpenAPIMockMethodNotAllowed  = errors.New("openapi mock method not allowed")
	errOpenAPIMockPreferenceInvalid = errors.New("openapi mock prefer header does not match any response")
	errOpenAPIMockResponsesMissing  = errors.New("openapi mock operation does not define responses")
	errOpenAPIMockResponseMissing   = errors.New("openapi mock operation did not expose a usable response")
	errOpenAPIMockContentEmpty      = errors.New("openapi mock response content is empty")
	errOpenAPIMockValueUnavailable  = errors.New("openapi mock value unavailable")
)

type compiledOpenAPIMockRoute struct {
	specPath            string
	document            *openapi3.T
	preferExamples      bool
	defaultStatus       string
	fallbackContentType string
}

type matchedOpenAPIOperation struct {
	pathTemplate string
	operation    *openapi3.Operation
}

type parsedPreferHeader struct {
	code    string
	example string
}

func newCompiledOpenAPIMockRoute(specPath string, mock *config.ReverseProxyMockOptions) (*compiledOpenAPIMockRoute, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	document, err := loader.LoadFromFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load reverse proxy OpenAPI file %q: %w", specPath, err)
	}
	if err := document.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("invalid reverse proxy OpenAPI file %q: %w", specPath, err)
	}

	item := &compiledOpenAPIMockRoute{
		specPath:       filepath.Clean(specPath),
		preferExamples: true,
	}
	if mock != nil {
		item.preferExamples = mock.PreferExamples
		item.defaultStatus = mock.DefaultStatus
		item.fallbackContentType = mock.FallbackContentType
	}
	item.document = document
	return item, nil
}

func (s *Server) serveOpenAPIMockRoute(w http.ResponseWriter, r *http.Request, route compiledReverseProxyRoute) {
	if route.mock == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	requestPath := rewriteMatchedPath(r.URL.Path, route.path, route.rewritePathPrefix)
	operation, err := route.mock.matchOperation(requestPath, r.Method)
	if err != nil {
		switch {
		case errors.Is(err, errOpenAPIMockMethodNotAllowed):
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		case errors.Is(err, errOpenAPIMockOperationNotFound):
			http.NotFound(w, r)
		default:
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	prefer := parsePreferHeader(r.Header.Get("Prefer"))
	responseRef, statusCode, err := route.mock.selectResponse(operation.operation, prefer)
	if err != nil {
		if errors.Is(err, errOpenAPIMockPreferenceInvalid) {
			http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
			return
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	response := responseRef.Value
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	for name, headerRef := range response.Headers {
		if headerRef == nil || headerRef.Value == nil || headerRef.Value.Schema == nil || headerRef.Value.Schema.Value == nil {
			continue
		}
		value, ok := route.mock.headerValue(headerRef.Value.Schema.Value)
		if ok {
			w.Header().Set(name, value)
		}
	}

	if statusCode == http.StatusNoContent || len(response.Content) == 0 {
		w.WriteHeader(statusCode)
		return
	}

	mediaTypeName, mediaType, err := route.mock.selectMediaType(response.Content, r.Header.Get("Accept"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
		return
	}

	body, err := route.mock.responseBody(mediaType, prefer)
	if err != nil {
		if errors.Is(err, errOpenAPIMockPreferenceInvalid) {
			http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
			return
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", mediaTypeName)
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

func (m *compiledOpenAPIMockRoute) matchOperation(requestPath, method string) (matchedOpenAPIOperation, error) {
	if m == nil || m.document == nil || m.document.Paths == nil {
		return matchedOpenAPIOperation{}, errOpenAPIMockOperationNotFound
	}

	normalizedPath := ensureLeadingSlash(requestPath)
	method = strings.ToUpper(strings.TrimSpace(method))

	var pathMatched bool
	for pathTemplate, item := range m.document.Paths.Map() {
		if item == nil || !matchOpenAPIPath(pathTemplate, normalizedPath) {
			continue
		}
		pathMatched = true
		if operation := item.GetOperation(method); operation != nil {
			return matchedOpenAPIOperation{
				pathTemplate: pathTemplate,
				operation:    operation,
			}, nil
		}
	}
	if pathMatched {
		return matchedOpenAPIOperation{}, errOpenAPIMockMethodNotAllowed
	}
	return matchedOpenAPIOperation{}, errOpenAPIMockOperationNotFound
}

func matchOpenAPIPath(template, requestPath string) bool {
	templateSegments := splitPathSegments(template)
	requestSegments := splitPathSegments(requestPath)
	if len(templateSegments) != len(requestSegments) {
		return false
	}
	for i := range templateSegments {
		left := templateSegments[i]
		right := requestSegments[i]
		if strings.HasPrefix(left, "{") && strings.HasSuffix(left, "}") {
			continue
		}
		if left != right {
			return false
		}
	}
	return true
}

func splitPathSegments(value string) []string {
	trimmed := strings.Trim(strings.TrimSpace(value), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func parsePreferHeader(value string) parsedPreferHeader {
	prefer := parsedPreferHeader{}
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		key, rawValue, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rawValue = strings.Trim(strings.TrimSpace(rawValue), "\"")
		switch key {
		case "code", "status":
			prefer.code = rawValue
		case "example":
			prefer.example = rawValue
		}
	}
	return prefer
}

func (m *compiledOpenAPIMockRoute) selectResponse(operation *openapi3.Operation, prefer parsedPreferHeader) (*openapi3.ResponseRef, int, error) {
	if operation == nil || operation.Responses == nil {
		return nil, 0, errOpenAPIMockResponsesMissing
	}

	if prefer.code != "" {
		if code, err := strconv.Atoi(prefer.code); err == nil {
			if response := operation.Responses.Status(code); response != nil {
				return response, code, nil
			}
		}
		return nil, 0, errOpenAPIMockPreferenceInvalid
	}

	if m.defaultStatus != "" {
		if code, err := strconv.Atoi(m.defaultStatus); err == nil {
			if response := operation.Responses.Status(code); response != nil {
				return response, code, nil
			}
		}
	}

	for _, candidate := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		if response := operation.Responses.Status(candidate); response != nil {
			return response, candidate, nil
		}
	}

	keys := make([]string, 0, len(operation.Responses.Map()))
	for key := range operation.Responses.Map() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		response := operation.Responses.Value(key)
		if response == nil {
			continue
		}
		if key == "default" {
			return response, http.StatusOK, nil
		}
		if len(key) == 3 && strings.HasSuffix(key, "XX") {
			code, _ := strconv.Atoi(string(key[0]) + "00")
			return response, code, nil
		}
		code, err := strconv.Atoi(key)
		if err == nil {
			return response, code, nil
		}
	}

	return nil, 0, errOpenAPIMockResponseMissing
}

func (m *compiledOpenAPIMockRoute) selectMediaType(content openapi3.Content, acceptHeader string) (string, *openapi3.MediaType, error) {
	if len(content) == 0 {
		return "", nil, nil
	}

	if acceptHeader != "" {
		for _, accepted := range parseAcceptHeader(acceptHeader) {
			for name, mediaType := range content {
				if acceptsMediaType(accepted, name) {
					return name, mediaType, nil
				}
			}
		}
	}

	if m.fallbackContentType != "" {
		if mediaType, ok := content[m.fallbackContentType]; ok {
			return m.fallbackContentType, mediaType, nil
		}
	}
	if mediaType, ok := content["application/json"]; ok {
		return "application/json", mediaType, nil
	}

	keys := make([]string, 0, len(content))
	for key := range content {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "", nil, errOpenAPIMockContentEmpty
	}
	return keys[0], content[keys[0]], nil
}

func parseAcceptHeader(value string) []string {
	var accepted []string
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		mediaType, _, err := mime.ParseMediaType(part)
		if err != nil {
			mediaType = part
		}
		accepted = append(accepted, strings.ToLower(mediaType))
	}
	return accepted
}

func acceptsMediaType(accepted, candidate string) bool {
	accepted = strings.ToLower(strings.TrimSpace(accepted))
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	if accepted == "*/*" || accepted == candidate {
		return true
	}
	leftType, leftSub, _ := strings.Cut(accepted, "/")
	rightType, _, ok := strings.Cut(candidate, "/")
	if !ok {
		return false
	}
	return leftType == rightType && leftSub == "*"
}

func (m *compiledOpenAPIMockRoute) responseBody(mediaType *openapi3.MediaType, prefer parsedPreferHeader) ([]byte, error) {
	if mediaType == nil {
		return nil, nil
	}

	value, err := m.mediaTypeValue(mediaType, prefer)
	if err != nil {
		if errors.Is(err, errOpenAPIMockValueUnavailable) {
			return nil, nil
		}
		return nil, err
	}
	return marshalMockValue(value)
}

func marshalMockValue(value any) ([]byte, error) {
	switch typed := value.(type) {
	case string:
		return []byte(typed), nil
	case []byte:
		return typed, nil
	default:
		return json.Marshal(typed)
	}
}

func (m *compiledOpenAPIMockRoute) mediaTypeValue(mediaType *openapi3.MediaType, prefer parsedPreferHeader) (any, error) {
	if mediaType == nil {
		return nil, errOpenAPIMockValueUnavailable
	}

	if prefer.example != "" {
		if mediaType.Examples == nil {
			return nil, errOpenAPIMockPreferenceInvalid
		}
		ref := mediaType.Examples[prefer.example]
		if ref == nil || ref.Value == nil {
			return nil, errOpenAPIMockPreferenceInvalid
		}
		return ref.Value.Value, nil
	}

	if m.preferExamples {
		if value, ok := firstOpenAPIExample(mediaType.Examples); ok {
			return value, nil
		}
		if mediaType.Example != nil {
			return mediaType.Example, nil
		}
	}

	if mediaType.Example != nil {
		return mediaType.Example, nil
	}
	if value, ok := firstOpenAPIExample(mediaType.Examples); ok {
		return value, nil
	}
	if mediaType.Schema != nil && mediaType.Schema.Value != nil && mediaType.Schema.Value.Example != nil {
		return mediaType.Schema.Value.Example, nil
	}
	if mediaType.Schema != nil {
		return synthesizeOpenAPIValue(mediaType.Schema, map[string]int{})
	}
	return nil, errOpenAPIMockValueUnavailable
}

func firstOpenAPIExample(examples openapi3.Examples) (any, bool) {
	if len(examples) == 0 {
		return nil, false
	}
	keys := make([]string, 0, len(examples))
	for key := range examples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ref := examples[key]
		if ref != nil && ref.Value != nil {
			return ref.Value.Value, true
		}
	}
	return nil, false
}

func synthesizeOpenAPIValue(ref *openapi3.SchemaRef, seen map[string]int) (any, error) {
	if ref == nil || ref.Value == nil {
		return nil, errOpenAPIMockValueUnavailable
	}
	if ref.Ref != "" {
		seen[ref.Ref]++
		if seen[ref.Ref] > 2 {
			return nil, errOpenAPIMockValueUnavailable
		}
		defer func() { seen[ref.Ref]-- }()
	}

	schema := ref.Value
	if schema.Default != nil {
		return schema.Default, nil
	}
	if schema.Example != nil {
		return schema.Example, nil
	}
	if len(schema.Enum) > 0 {
		return schema.Enum[0], nil
	}
	if len(schema.OneOf) > 0 {
		return synthesizeOpenAPIValue(schema.OneOf[0], seen)
	}
	if len(schema.AnyOf) > 0 {
		return synthesizeOpenAPIValue(schema.AnyOf[0], seen)
	}
	if len(schema.AllOf) > 0 {
		merged := map[string]any{}
		for _, part := range schema.AllOf {
			value, err := synthesizeOpenAPIValue(part, seen)
			if err != nil {
				if errors.Is(err, errOpenAPIMockValueUnavailable) {
					continue
				}
				return nil, err
			}
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			maps.Copy(merged, object)
		}
		if len(merged) > 0 {
			return merged, nil
		}
	}
	switch {
	case schema.Type != nil && schema.Type.Includes("object"):
		result := map[string]any{}
		required := map[string]struct{}{}
		for _, key := range schema.Required {
			required[key] = struct{}{}
		}
		keys := make([]string, 0, len(schema.Properties))
		for key := range schema.Properties {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			property := schema.Properties[key]
			if len(required) > 0 {
				if _, ok := required[key]; !ok {
					continue
				}
			}
			value, err := synthesizeOpenAPIValue(property, seen)
			if err != nil {
				if errors.Is(err, errOpenAPIMockValueUnavailable) {
					continue
				}
				return nil, err
			}
			result[key] = value
		}
		if len(result) == 0 && schema.AdditionalProperties.Schema != nil {
			value, err := synthesizeOpenAPIValue(schema.AdditionalProperties.Schema, seen)
			if err != nil {
				if errors.Is(err, errOpenAPIMockValueUnavailable) {
					return result, nil
				}
				return nil, err
			}
			result["property"] = value
		}
		return result, nil
	case schema.Type != nil && schema.Type.Includes("array"):
		value, err := synthesizeOpenAPIValue(schema.Items, seen)
		if err != nil {
			if errors.Is(err, errOpenAPIMockValueUnavailable) {
				return []any{}, nil
			}
			return nil, err
		}
		return []any{value}, nil
	case schema.Type != nil && schema.Type.Includes("integer"):
		return 1, nil
	case schema.Type != nil && schema.Type.Includes("number"):
		return 1.0, nil
	case schema.Type != nil && schema.Type.Includes("boolean"):
		return true, nil
	}

	switch schema.Format {
	case "date":
		return "2026-04-20", nil
	case "date-time":
		return "2026-04-20T00:00:00Z", nil
	case "uuid":
		return "00000000-0000-0000-0000-000000000000", nil
	case "email":
		return "user@example.com", nil
	}
	return "string", nil
}

func (m *compiledOpenAPIMockRoute) headerValue(schema *openapi3.Schema) (string, bool) {
	if schema == nil {
		return "", false
	}
	if schema.Example != nil {
		return fmt.Sprint(schema.Example), true
	}
	if schema.Default != nil {
		return fmt.Sprint(schema.Default), true
	}
	if len(schema.Enum) > 0 {
		return fmt.Sprint(schema.Enum[0]), true
	}
	return "", false
}

func ensureLeadingSlash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return "/"
	}
	if strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}
