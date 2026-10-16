package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogsRejectMalformedURLParametersBeforeDatabaseAccess(t *testing.T) {
	for _, rawQuery := range []string{
		"cursor=%%%",
		"query=action%20eq%20deny%",
		"query=action%20eq%20deny&cursor=%zz",
		"query=action%20eq%20deny;action%20eq%20allow",
		"from=%&to=2026-10-16T00:00:00Z",
		"sort=%zz&limit=1",
		"limit=%",
	} {
		t.Run(rawQuery, func(t *testing.T) {
			// No store is configured: discarded parameters must never reach a
			// default or broadened database search.
			server := &Server{}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/logs?"+rawQuery, nil)
			server.logs(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Invalid query parameters") {
				t.Fatalf("malformed URL accepted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestLogsDecodesEscapedCursorBeforeValidation(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/logs?cursor=%25%25%25", nil)
	(&Server{}).logs(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Invalid cursor") {
		t.Fatalf("decoded cursor validation changed: status=%d body=%s", response.Code, response.Body.String())
	}
}
