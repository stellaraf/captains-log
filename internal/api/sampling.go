package api

import (
	"context"
	"log/slog"
	"time"
)

// StartSampling measures storage even when nobody opens the administration page.
// Only metadata samples expire here; firewall event retention remains ClickHouse TTL.
func (s *Server) StartSampling(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
			rows, err := s.Store.CH.Rows(attempt, "SELECT coalesce(sum(bytes_on_disk),0) AS database_bytes,coalesce(sum(rows),0) AS events FROM system.parts WHERE active AND database='nebulalog' AND table='events'", nil)
			if err == nil && len(rows) == 1 {
				_, err = s.Store.PG.Exec(attempt, "INSERT INTO storage_samples(database_bytes,events) VALUES($1,$2)", int64(number(rows[0]["database_bytes"])), int64(number(rows[0]["events"])))
			}
			if err == nil {
				_, err = s.Store.PG.Exec(attempt, "DELETE FROM storage_samples WHERE sampled_at < now()-interval '30 days'")
			}
			if err != nil && ctx.Err() == nil {
				slog.Warn("storage sample unavailable; next scheduled sample will retry")
			}
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
