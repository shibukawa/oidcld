package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type diagnosticErrorResponse struct {
	Status     int            `json:"status"`
	Code       string         `json:"code"`
	Reason     string         `json:"reason"`
	Message    string         `json:"message"`
	Details    map[string]any `json:"details,omitempty"`
	Suggestion string         `json:"suggestion,omitempty"`
}

func writeDiagnosticError(w http.ResponseWriter, r *http.Request, status int, code, reason, message string, details map[string]any, suggestion string) {
	if wantsJSONError(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(diagnosticErrorResponse{
			Status:     status,
			Code:       code,
			Reason:     reason,
			Message:    message,
			Details:    details,
			Suggestion: suggestion,
		})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s\n\n%s\n", http.StatusText(status), message)
	if len(details) > 0 {
		_, _ = fmt.Fprintln(w)
		for key, value := range details {
			_, _ = fmt.Fprintf(w, "%s: %v\n", key, value)
		}
	}
	if strings.TrimSpace(suggestion) != "" {
		_, _ = fmt.Fprintf(w, "\nSuggestion: %s\n", suggestion)
	}
}

func wantsJSONError(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json")
}
