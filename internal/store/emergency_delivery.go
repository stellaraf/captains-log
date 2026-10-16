package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func emergencyDeliveryConnection(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Conn, func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock_shared($1)", EmergencyLockID); err != nil {
		conn.Hijack().Close(context.Background())
		return nil, nil, err
	}
	return conn, func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var ok bool
		if e := conn.QueryRow(cleanup, "SELECT pg_advisory_unlock_shared($1)", EmergencyLockID).Scan(&ok); e != nil || !ok {
			conn.Hijack().Close(cleanup)
		} else {
			conn.Release()
		}
	}, nil
}

// A committed insertion reservation outlives session-lock loss. A delayed HTTP
// INSERT cannot then race a purge of its category/day, including parse failures.
func (s *Store) insertEmergencyGuarded(ctx context.Context, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}
	if len(rows) > 10000 {
		return errors.New("insertion batch exceeds emergency coordination bound")
	}
	if _, err := s.readHostMaintenance(); err != nil {
		return err
	}
	conn, release, err := emergencyDeliveryConnection(ctx, s.PG)
	if err != nil {
		return err
	}
	defer release()
	policy, err := readEmergencyPolicy(ctx, conn)
	if err != nil {
		return err
	}
	gate, err := s.effectiveEmergencyMaintenance(ctx, conn)
	if err != nil {
		return err
	}
	if gate.DeliveryHeld {
		return errors.New("Host maintenance is holding delivery; durable spool is retained")
	}
	state, err := readEmergencyStatus(ctx, conn)
	if err != nil {
		return err
	}
	pending, err := pendingEmergency(ctx, conn)
	if err != nil {
		return err
	}
	if pending != nil {
		return ErrStoragePressure
	}
	if state.Identity == nil {
		return ErrStoragePressure
	}
	if policy.Enabled && (state.Active || state.State != "normal" || state.ObservedAt == nil || time.Since(*state.ObservedAt) < 0 || time.Since(*state.ObservedAt) > EmergencyObservationMaxAge) {
		return ErrStoragePressure
	}
	identity, err := observeEmergency(ctx, s.CH, time.Now())
	if err != nil {
		return err
	}
	if identity.Identity != *state.Identity {
		return errors.New("ClickHouse delivery identity changed; spool retained")
	}
	if policy.Enabled && identity.UsedPercent >= float64(policy.TriggerPercent) {
		return ErrStoragePressure
	}
	partitions := map[emergencyInsertPartition]bool{}
	for _, row := range rows {
		ts, e := time.Parse(time.RFC3339Nano, fmt.Sprint(row["ingested_at"]))
		if e != nil {
			return errors.New("invalid ingestion timestamp; partition cannot be fenced")
		}
		kind, ok := row["log_type"].(string)
		if !ok || kind == "" || len(kind) > 128 {
			return errors.New("invalid insertion category")
		}
		partitions[emergencyInsertPartition{kind, ts.UTC().Format("2006-01-02")}] = true
	}
	ordered := make([]emergencyInsertPartition, 0, len(partitions))
	for p := range partitions {
		ordered = append(ordered, p)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].LogType != ordered[j].LogType {
			return ordered[i].LogType < ordered[j].LogType
		}
		return ordered[i].Day < ordered[j].Day
	})
	id, queryID := emergencyID(), emergencyID()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize only reservation bookkeeping, not whole HTTP insert requests.
	if _, err = tx.Exec(ctx, "SELECT singleton FROM storage_emergency_state WHERE singleton=true FOR UPDATE"); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM storage_emergency_inserts").Scan(&count); err != nil {
		return err
	}
	if count >= 4096 {
		return errors.New("insertion uncertainty evidence is full; operator review required, spool retained")
	}
	if _, err = tx.Exec(ctx, "INSERT INTO storage_emergency_inserts(id,table_uuid,partitions,query_id) VALUES($1,$2,$3,$4)", id, identity.Identity.TableUUID, emergencyJSON(ordered), queryID); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	// Never issue the INSERT after losing this session before dispatch. Its
	// retained reservation is deliberately conservative even in this case.
	if err = conn.Ping(ctx); err != nil {
		return err
	}
	if err = s.CH.InsertRowsWithQueryID(ctx, rows, queryID); err != nil {
		return err
	}
	// The actual server acknowledgement is sufficient to acknowledge the WAL;
	// reservation cleanup failure only excludes this partition from later purge.
	if _, err = conn.Exec(ctx, "DELETE FROM storage_emergency_inserts WHERE id=$1 AND query_id=$2", id, queryID); err != nil {
		slog.Error("acknowledged insertion reservation retained; emergency removal excludes its partitions", "attempt", id)
	}
	return nil
}
