package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stellaraf/captains-log/internal/identity"
)

func TestIdentityErrorsCannotWriteInvalidHTTPStatus(t *testing.T) {
	for _, test := range []struct {
		kind         string
		status, want int
	}{{"validation", 0, 400}, {"conflict", 0, 409}, {"upstream", 0, 503}, {"upstream", 401, 503}, {"upstream", 403, 503}, {"unknown", 0, 503}, {"validation", -1, 400}, {"validation", 200, 400}} {
		response := httptest.NewRecorder()
		identityError(response, &identity.Error{Kind: test.kind, StatusCode: test.status, Message: "Safe configuration error"})
		if response.Code != test.want {
			t.Fatalf("status=%d want=%d", response.Code, test.want)
		}
	}
}

func TestIdentityUploadLimitDoesNotRelaxOtherRequestLimits(t *testing.T) {
	large := `{"metadata":"` + strings.Repeat("x", 70000) + `"}`
	request := httptest.NewRequest("POST", "/", strings.NewReader(large))
	response := httptest.NewRecorder()
	var input struct {
		Metadata string `json:"metadata"`
	}
	if decode(response, request, &input) {
		t.Fatal("normal body limit was widened")
	}
	request = httptest.NewRequest("POST", "/", strings.NewReader(large))
	response = httptest.NewRecorder()
	if !decodeLimit(response, request, &input, 400<<10) {
		t.Fatal("bounded identity upload was rejected")
	}
	request = httptest.NewRequest("POST", "/", strings.NewReader(large+` {}`))
	response = httptest.NewRecorder()
	if decodeLimit(response, request, &input, 400<<10) {
		t.Fatal("multiple JSON documents accepted")
	}
}
