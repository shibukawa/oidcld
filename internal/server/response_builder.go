package server

import (
	"fmt"
	"maps"
	"net/url"
	"strings"
)

// ResponseBuilder helps build authorization responses with different response modes
type ResponseBuilder struct {
	redirectURI  string
	responseMode string
	parameters   map[string]string
}

// NewResponseBuilder creates a new response builder
func NewResponseBuilder(redirectURI, responseMode string) *ResponseBuilder {
	// Default to query mode if not specified or invalid
	if responseMode == "" {
		responseMode = "query"
	}

	return &ResponseBuilder{
		redirectURI:  redirectURI,
		responseMode: responseMode,
		parameters:   make(map[string]string),
	}
}

// AddParameter adds a parameter to the response
func (rb *ResponseBuilder) AddParameter(key, value string) *ResponseBuilder {
	if value != "" {
		rb.parameters[key] = value
	}
	return rb
}

// AddParameters adds multiple parameters to the response
func (rb *ResponseBuilder) AddParameters(params map[string]string) *ResponseBuilder {
	for key, value := range params {
		rb.AddParameter(key, value)
	}
	return rb
}

// BuildRedirectURL builds the final redirect URL based on the response mode
func (rb *ResponseBuilder) BuildRedirectURL() (string, error) {
	// Parse the redirect URI
	redirectURL, err := url.Parse(rb.redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}

	// Apply response mode
	switch strings.ToLower(rb.responseMode) {
	case "fragment":
		return rb.buildFragmentResponse(redirectURL)
	case "form_post":
		// form_post mode is handled differently (returns HTML form)
		// For now, fall back to query mode
		// NOTE: form_post mode implementation is planned for future enhancement
		fallthrough
	case "query", "":
		return rb.buildQueryResponse(redirectURL)
	default:
		// Unknown response mode, default to query
		return rb.buildQueryResponse(redirectURL)
	}
}

// buildQueryResponse builds a query parameter response
func (rb *ResponseBuilder) buildQueryResponse(redirectURL *url.URL) (string, error) {
	if len(rb.parameters) == 0 {
		return redirectURL.String(), nil
	}

	// Merge with existing query parameters
	existingQuery := redirectURL.Query()

	// Add new parameters to existing ones
	for key, value := range rb.parameters {
		existingQuery.Set(key, value)
	}

	redirectURL.RawQuery = existingQuery.Encode()
	return redirectURL.String(), nil
}

// buildFragmentResponse builds a fragment parameter response
func (rb *ResponseBuilder) buildFragmentResponse(redirectURL *url.URL) (string, error) {
	if len(rb.parameters) == 0 {
		return redirectURL.String(), nil
	}

	// For fragment mode, we use string concatenation to avoid double encoding issues
	// with Go's url.URL.Fragment and url.URL.RawFragment fields
	fragmentParts := make([]string, 0, len(rb.parameters))
	for key, value := range rb.parameters {
		// Manually encode each key and value
		encodedKey := url.QueryEscape(key)
		encodedValue := url.QueryEscape(value)
		fragmentParts = append(fragmentParts, encodedKey+"="+encodedValue)
	}

	// Clear query parameters for fragment mode (OAuth 2.0 spec requirement)
	redirectURL.RawQuery = ""

	// Build the final URL using string concatenation
	// This avoids all the encoding issues with url.URL fields
	baseURL := redirectURL.String()
	fragmentString := strings.Join(fragmentParts, "&")

	return baseURL + "#" + fragmentString, nil
}

// GetResponseMode returns the current response mode
func (rb *ResponseBuilder) GetResponseMode() string {
	return rb.responseMode
}

// GetParameters returns a copy of the current parameters
func (rb *ResponseBuilder) GetParameters() map[string]string {
	return maps.Clone(rb.parameters)
}

// IsFragmentMode returns true if the response mode is fragment
func (rb *ResponseBuilder) IsFragmentMode() bool {
	return strings.ToLower(rb.responseMode) == "fragment"
}

// IsQueryMode returns true if the response mode is query (or default)
func (rb *ResponseBuilder) IsQueryMode() bool {
	mode := strings.ToLower(rb.responseMode)
	return mode == "query" || mode == ""
}
