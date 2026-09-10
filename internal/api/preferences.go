package api

import (
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/stellaraf/captains-log/internal/auth"
)

type Preferences struct {
	Theme         string `json:"theme"`
	Density       string `json:"density"`
	RailCollapsed bool   `json:"rail_collapsed"`
}

func (s *Server) preferences(w http.ResponseWriter, r *http.Request) {
	owner := auth.Current(r.Context()).ID
	p := Preferences{Theme: "system", Density: "compact"}
	if r.Method == http.MethodGet {
		err := s.Store.PG.QueryRow(r.Context(), "SELECT theme,density,rail_collapsed FROM user_preferences WHERE owner_id=$1", owner).Scan(&p.Theme, &p.Density, &p.RailCollapsed)
		if err != nil && err != pgx.ErrNoRows {
			databaseError(w, err)
			return
		}
		respond(w, http.StatusOK, p)
		return
	}
	if !decode(w, r, &p) {
		return
	}
	if (p.Theme != "system" && p.Theme != "light" && p.Theme != "dark") || (p.Density != "compact" && p.Density != "comfortable") {
		problem(w, http.StatusBadRequest, "Choose Light, Dark or System and compact or comfortable density")
		return
	}
	_, err := s.Store.PG.Exec(r.Context(), `INSERT INTO user_preferences(owner_id,theme,density,rail_collapsed) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id) DO UPDATE SET theme=EXCLUDED.theme,density=EXCLUDED.density,rail_collapsed=EXCLUDED.rail_collapsed,updated_at=now()`, owner, p.Theme, p.Density, p.RailCollapsed)
	if err != nil {
		databaseError(w, err)
		return
	}
	respond(w, http.StatusOK, p)
}
