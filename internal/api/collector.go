package api

import (
	"errors"
	"github.com/stellaraf/captains-log/internal/ingest"
	"time"
)

func (s *Server) collectorStats() (ingest.Stats, error) {
	if s.Collector != nil {
		return s.Collector.Snapshot(), nil
	}
	if s.Config.CollectorStatusPath != "" {
		return ingest.ReadStatus(s.Config.CollectorStatusPath, time.Now())
	}
	return ingest.Stats{}, errors.New("collector observation is not configured")
}
