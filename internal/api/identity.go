package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/identity"
)

func identityError(w http.ResponseWriter, err error) {
	var safe *identity.Error
	if errors.As(err, &safe) {
		// Upstream service credentials are independent of the browser session.
		// Never turn a Keycloak management 401 into an interactive login loop.
		status := map[string]int{"validation": 400, "disabled": 403, "conflict": 409, "upstream": 503}[safe.Kind]
		if status == 0 {
			status = http.StatusServiceUnavailable
		}
		problem(w, status, safe.Message)
		return
	}
	problem(w, http.StatusServiceUnavailable, "Identity configuration could not complete. Check appliance diagnostics.")
}

func (s *Server) identityProviders(w http.ResponseWriter, r *http.Request) {
	if s.Identity == nil {
		respond(w, http.StatusOK, map[string]any{"available": false, "providers": []any{}, "message": "Identity management is not configured for this deployment. Setup instructions remain available."})
		return
	}
	providers, err := s.Identity.List(r.Context())
	if err != nil {
		identityError(w, err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"available": true, "providers": providers})
}

func (s *Server) identityProvider(w http.ResponseWriter, r *http.Request) {
	if s.Identity == nil {
		problem(w, http.StatusServiceUnavailable, "Identity management is not configured for this deployment")
		return
	}
	alias := r.PathValue("alias")
	if r.Method == http.MethodGet {
		provider, err := s.Identity.Inspect(r.Context(), alias)
		if err != nil {
			identityError(w, err)
			return
		}
		respond(w, http.StatusOK, map[string]any{"provider": provider})
		return
	}
	var setup identity.Setup
	if !decodeLimit(w, r, &setup, 400<<10) {
		return
	}
	setup.Alias = alias
	preview, err := s.Identity.Preview(setup)
	if err != nil {
		identityError(w, err)
		return
	}
	if r.Method == http.MethodPost {
		respond(w, http.StatusOK, map[string]any{"preview": preview})
		return
	}
	// Persist intent before crossing the Keycloak boundary. The audit contains
	// the public configuration's digest, never a raw assertion or credential.
	operation := uuid()
	hash := sha256.Sum256([]byte(setup.MetadataXML))
	detail, _ := json.Marshal(map[string]any{"operation_id": operation, "metadata_sha256": hex.EncodeToString(hash[:]), "enabled": setup.Enabled, "groups": setup.Groups})
	_, err = s.Store.PG.Exec(r.Context(), "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,'identity.save.started',$2,$3)", auth.Current(r.Context()).ID, alias, detail)
	if err != nil {
		databaseError(w, err)
		return
	}
	provider, saveErr := s.Identity.Save(r.Context(), setup)
	result := "identity.save.completed"
	if saveErr != nil {
		result = "identity.save.failed"
	}
	auditContext, stopAudit := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer stopAudit()
	_, err = s.Store.PG.Exec(auditContext, "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,$2,$3,$4)", auth.Current(r.Context()).ID, result, alias, detail)
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "Identity settings may have changed, but the result audit could not be saved. Reload provider configuration before retrying.")
		return
	}
	if saveErr != nil {
		identityError(w, saveErr)
		return
	}
	respond(w, http.StatusOK, map[string]any{"provider": provider})
}

func (s *Server) identityTest(w http.ResponseWriter, r *http.Request) {
	if s.Identity == nil {
		problem(w, http.StatusServiceUnavailable, "Identity management is not configured for this deployment")
		return
	}
	status, err := s.Identity.TestStatus(r.Context(), r.PathValue("alias"))
	if err != nil {
		identityError(w, err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"status": status})
}

func (s *Server) identityState(w http.ResponseWriter, r *http.Request) {
	if s.Identity == nil {
		problem(w, http.StatusServiceUnavailable, "Identity management is not configured for this deployment")
		return
	}
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Enabled == nil {
		problem(w, http.StatusBadRequest, "Specify whether provider sign-in should be enabled")
		return
	}
	alias := r.PathValue("alias")
	if alias != "okta" && alias != "entra" {
		problem(w, http.StatusBadRequest, "Provider alias must be okta or entra")
		return
	}
	detail, _ := json.Marshal(map[string]any{"operation_id": uuid(), "enabled": *input.Enabled})
	_, err := s.Store.PG.Exec(r.Context(), "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,'identity.state.started',$2,$3)", auth.Current(r.Context()).ID, alias, detail)
	if err != nil {
		databaseError(w, err)
		return
	}
	provider, stateErr := s.Identity.SetEnabled(r.Context(), alias, *input.Enabled)
	result := "identity.state.completed"
	if stateErr != nil {
		result = "identity.state.failed"
	}
	auditContext, stopAudit := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer stopAudit()
	_, err = s.Store.PG.Exec(auditContext, "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,$2,$3,$4)", auth.Current(r.Context()).ID, result, alias, detail)
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "Provider sign-in state may have changed, but the result audit could not be saved. Reload provider configuration before retrying.")
		return
	}
	if stateErr != nil {
		identityError(w, stateErr)
		return
	}
	respond(w, http.StatusOK, map[string]any{"provider": provider})
}
