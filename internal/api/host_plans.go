package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stellaraf/captains-log/internal/hostcontrol"
)

// HostPlanReader is a trusted in-process dependency. Production uses the
// root-authenticated Unix client; requests cannot select another implementation.
type HostPlanReader interface {
	Capabilities(context.Context, hostcontrol.Actor) (hostcontrol.Capabilities, error)
	CreatePlan(context.Context, hostcontrol.Actor, string) (hostcontrol.Plan, error)
	LookupPlan(context.Context, hostcontrol.Actor, string, string) (hostcontrol.Plan, error)
}

func ValidHostPlanOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && origin != "" && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(origin, "\\\r\n\t ") && u.String() == origin
}

func (s *Server) hostPlanActor(w http.ResponseWriter, r *http.Request) (hostcontrol.Actor, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if s.Auth == nil || len(r.Header.Values("Authorization")) != 1 {
		problem(w, 401, "A current administrator session is required.")
		return hostcontrol.Actor{}, false
	}
	a, err := hostcontrol.ActorFromContext(r.Context(), s.Auth.ClientID, time.Now())
	if err != nil {
		problem(w, 401, "A current administrator session is required.")
		return hostcontrol.Actor{}, false
	}
	return a, true
}

func hostPlanError(w http.ResponseWriter, err error) {
	status, code := 503, "host_unavailable"
	var refusal *hostcontrol.Refusal
	if errors.As(err, &refusal) {
		switch refusal.Code {
		case "invalid_request":
			status, code = 400, "invalid_request"
		case "plan_unavailable":
			status, code = 404, "plan_unavailable"
		case "plan_expired":
			status, code = 410, "plan_expired"
		case "resource_changed":
			status, code = 409, "resource_changed"
		case "manager_busy", "journal_full":
			code = refusal.Code
		}
	}
	respond(w, status, map[string]any{"error": "The host plan is unavailable. Refresh the host measurements before reviewing again.", "code": code, "execution_available": false})
}

func (s *Server) hostPlanCapabilities(w http.ResponseWriter, r *http.Request) {
	a, ok := s.hostPlanActor(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		problem(w, 400, "This request does not accept query parameters.")
		return
	}
	if s.HostPlans == nil {
		hostPlanError(w, hostcontrol.ErrUnavailable)
		return
	}
	value, err := s.HostPlans.Capabilities(r.Context(), a)
	if err != nil {
		hostPlanError(w, err)
		return
	}
	respond(w, 200, value)
}

func (s *Server) hostPlanCreate(w http.ResponseWriter, r *http.Request) {
	a, ok := s.hostPlanActor(w, r)
	if !ok {
		return
	}
	if !ValidHostPlanOrigin(s.Config.HostPlanPublicOrigin) {
		hostPlanError(w, hostcontrol.ErrUnavailable)
		return
	}
	origins, sites := r.Header.Values("Origin"), r.Header.Values("Sec-Fetch-Site")
	if len(origins) != 1 || origins[0] != s.Config.HostPlanPublicOrigin || len(sites) > 1 || (len(sites) == 1 && sites[0] != "same-origin" && sites[0] != "none") {
		problem(w, 403, "This review must be requested from the configured appliance origin.")
		return
	}
	if r.URL.RawQuery != "" {
		problem(w, 400, "This request does not accept query parameters.")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		problem(w, 415, "Use an application/json request.")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || !utf8.Valid(raw) || !uniqueStatusJSON(json.NewDecoder(bytes.NewReader(raw)), 0) {
		problem(w, 400, "Invalid host plan request.")
		return
	}
	var shape map[string]json.RawMessage
	var parameters map[string]json.RawMessage
	if json.Unmarshal(raw, &shape) != nil || len(shape) != 2 || shape["operation"] == nil ||
		json.Unmarshal(shape["parameters"], &parameters) != nil || len(parameters) != 1 || parameters["pool_id"] == nil {
		problem(w, 400, "Invalid host plan request.")
		return
	}
	var request *struct {
		Operation  string                  `json:"operation"`
		Parameters *hostcontrol.Parameters `json:"parameters"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request == nil || request.Operation != "storage.grow" || request.Parameters == nil || !hostcontrol.ValidUUID(request.Parameters.PoolID) {
		problem(w, 400, "Invalid host plan request.")
		return
	}
	if s.HostPlans == nil {
		hostPlanError(w, hostcontrol.ErrUnavailable)
		return
	}
	value, err := s.HostPlans.CreatePlan(r.Context(), a, request.Parameters.PoolID)
	if err != nil {
		hostPlanError(w, err)
		return
	}
	respond(w, 201, value)
}

func (s *Server) hostPlanLookup(w http.ResponseWriter, r *http.Request) {
	a, ok := s.hostPlanActor(w, r)
	if !ok {
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 1 || len(q["digest"]) != 1 || !hostcontrol.ValidUUID(r.PathValue("id")) || !hostcontrol.ValidDigest(q.Get("digest")) {
		problem(w, 400, "An exact plan ID and digest are required.")
		return
	}
	if s.HostPlans == nil {
		hostPlanError(w, hostcontrol.ErrUnavailable)
		return
	}
	value, err := s.HostPlans.LookupPlan(r.Context(), a, r.PathValue("id"), q.Get("digest"))
	if err != nil {
		hostPlanError(w, err)
		return
	}
	respond(w, 200, value)
}
