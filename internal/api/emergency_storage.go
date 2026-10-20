package api

import (
	"errors"
	"net/http"

	"github.com/stellaraf/captains-log/internal/auth"
	"github.com/stellaraf/captains-log/internal/store"
)

func (s *Server) emergencyStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var request struct {
			ExpectedRevision int64          `json:"expected_revision"`
			Enabled          *bool          `json:"enabled"`
			TriggerPercent   int            `json:"trigger_percent"`
			RecoverPercent   int            `json:"recover_percent"`
			MinimumDays      map[string]int `json:"minimum_days"`
		}
		if !decode(w, r, &request) {
			return
		}
		p := store.EmergencyPolicy{Revision: request.ExpectedRevision + 1, Enabled: request.Enabled != nil && *request.Enabled, TriggerPercent: request.TriggerPercent, RecoverPercent: request.RecoverPercent, MinimumDays: request.MinimumDays}
		if err := p.Validate(); err != nil || request.ExpectedRevision < 1 || request.Enabled == nil {
			problem(w, 400, "Require current revision, trigger 90–99%, recovery 70% to below trigger, and every returned category minimum from 1–3650 whole days")
			return
		}
		if err := s.Store.UpdateEmergencyPolicy(r.Context(), auth.Current(r.Context()).ID, request.ExpectedRevision, p); err != nil {
			if errors.Is(err, store.ErrEmergencyRevision) || errors.Is(err, store.ErrEmergencyPending) {
				problem(w, http.StatusConflict, err.Error())
			} else {
				databaseError(w, err)
			}
			return
		}
	}
	v, err := s.Store.Emergency(r.Context())
	if err != nil {
		databaseError(w, err)
		return
	}
	respond(w, http.StatusOK, v)
}
