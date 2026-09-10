package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFailClosed(t *testing.T) {
	a := Auth{}
	w := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("unauthenticated request reached handler") })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestRoles(t *testing.T) {
	if Role([]string{"other", "VIEWER", "ADMINISTRATOR"}) != "ADMINISTRATOR" || Role([]string{"admin"}) != "" {
		t.Fatal("incorrect role mapping")
	}
	w := httptest.NewRecorder()
	Require("ADMINISTRATOR", func(w http.ResponseWriter, r *http.Request) { t.Fatal("missing identity allowed") })(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
