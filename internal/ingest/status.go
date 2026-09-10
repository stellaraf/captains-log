package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// StatusFile is a short-lived observation shared by the separate collector and
// API containers. It is not a durable event, acknowledgment, or recovery journal.
type StatusFile struct {
	Schema     int       `json:"schema"`
	ObservedAt time.Time `json:"observed_at"`
	Stats      Stats     `json:"stats"`
}

const StatusMaxAge = 10 * time.Second

func WriteStatus(path string, stats Stats, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".collector-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(StatusFile{Schema: 1, ObservedAt: now.UTC(), Stats: stats})
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func ReadStatus(path string, now time.Time) (Stats, error) {
	var empty Stats
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return empty, errors.New("collector observation is missing or unsafe")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, errors.New("collector observation is unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() > 64*1024 {
		return empty, errors.New("collector observation changed or exceeds limits")
	}
	var value StatusFile
	decoder := json.NewDecoder(io.LimitReader(f, 64*1024+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil {
		return empty, errors.New("collector observation is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || value.Schema != 1 || value.ObservedAt.IsZero() ||
		now.Sub(value.ObservedAt) > StatusMaxAge || value.ObservedAt.Sub(now) > 2*time.Second {
		return empty, errors.New("collector observation is stale or invalid")
	}
	return value.Stats, nil
}

// PublishStatus never blocks ingestion on an unavailable telemetry destination.
// The reader rejects stale observations; publication failures are reported.
func (c *Collector) PublishStatus(ctx context.Context, path string, report func(error)) {
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	defer os.Remove(path)
	for {
		if err := WriteStatus(path, c.Snapshot(), time.Now()); err != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
