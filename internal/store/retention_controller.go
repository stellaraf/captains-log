package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const retentionPartitionBatch = 32

func retentionInsertionFence(a *RetentionAction, partitions map[emergencyInsertPartition]bool) error {
	if a == nil {
		return nil
	}
	for _, p := range a.Partitions {
		if partitions[emergencyInsertPartition{p.LogType, p.PartitionDay}] {
			return errors.New("Normal retention removal fences this ingestion day; durable spool is retained")
		}
	}
	return nil
}

type RetentionAction struct {
	ID         string               `json:"id"`
	State      string               `json:"state"`
	QueryID    string               `json:"query_id"`
	Policy     Retention            `json:"policy"`
	At         time.Time            `json:"at"`
	Identity   EmergencyIdentity    `json:"identity"`
	Partitions []EmergencyPartition `json:"partitions"`
}

func pendingRetention(ctx context.Context, q emergencyQuerier) (*RetentionAction, error) {
	var raw []byte
	var a RetentionAction
	err := q.QueryRow(ctx, "SELECT id::text,state,plan FROM retention_actions WHERE completed_at IS NULL").Scan(&a.ID, &a.State, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id, state := a.ID, a.State
	if err = json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if a.ID != id || a.State != state || !emergencyUUID.MatchString(a.ID) || !emergencyUUID.MatchString(a.QueryID) || !emergencyUUID.MatchString(a.Identity.TableUUID) || a.Policy.Validate() != nil || a.At.IsZero() || len(a.Partitions) < 1 || len(a.Partitions) > retentionPartitionBatch {
		return nil, errors.New("Invalid retained normal-removal intent")
	}
	seen := map[string]bool{}
	for _, p := range a.Partitions {
		if !emergencyPartitionID.MatchString(p.PartitionID) || seen[p.PartitionID] || !retentionDayExpired(a.Policy, p.LogType, p.PartitionDay, a.At) || len(p.Parts) == 0 || p.Rows == 0 {
			return nil, errors.New("Invalid retained normal-removal partition")
		}
		seen[p.PartitionID] = true
	}
	return &a, nil
}

func retentionDayExpired(p Retention, kind, day string, now time.Time) bool {
	t, err := time.Parse("2006-01-02", day)
	return err == nil && !t.AddDate(0, 0, 1).After(now.UTC().AddDate(0, 0, -p.Days(kind)))
}

func eligibleRetentionPartitions(rows []map[string]any, p Retention, now time.Time) ([]EmergencyPartition, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	out := []EmergencyPartition{}
	for _, row := range rows {
		value, err := emergencyString(row, "partition")
		if err != nil {
			return nil, err
		}
		m := emergencyPartitionValue.FindStringSubmatch(value)
		if m == nil {
			return nil, errors.New("Unrecognized normal-retention partition; no removal authorized")
		}
		if !retentionDayExpired(p, m[1], m[2], now) {
			continue
		}
		id, err := emergencyString(row, "partition_id")
		if err != nil || !emergencyPartitionID.MatchString(id) {
			return nil, errors.New("Invalid retention partition ID")
		}
		n, err := emergencyUint(row, "rows")
		if err != nil {
			return nil, err
		}
		size, err := emergencyUint(row, "bytes_on_disk")
		if err != nil {
			return nil, err
		}
		parts, ok := row["parts"].([]EmergencyPart)
		if !ok || len(parts) == 0 || n == 0 || row["disk_name"] != "default" {
			return nil, errors.New("Retention partition evidence incomplete")
		}
		out = append(out, EmergencyPartition{PartitionID: id, LogType: m[1], PartitionDay: m[2], Rows: n, Bytes: size, Parts: parts})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PartitionDay != out[j].PartitionDay {
			return out[i].PartitionDay < out[j].PartitionDay
		}
		return out[i].PartitionID < out[j].PartitionID
	})
	return out, nil
}

func retentionDropSQL(partitions []EmergencyPartition) (string, map[string]string, error) {
	if len(partitions) < 1 || len(partitions) > retentionPartitionBatch {
		return "", nil, errors.New("Retention dispatch exceeds partition bound")
	}
	clauses := []string{}
	params := map[string]string{}
	seen := map[string]bool{}
	for i, p := range partitions {
		if !emergencyPartitionID.MatchString(p.PartitionID) || seen[p.PartitionID] {
			return "", nil, errors.New("Invalid or repeated retention partition")
		}
		seen[p.PartitionID] = true
		key := fmt.Sprintf("retention_partition_%d", i)
		params[key] = p.PartitionID
		clauses = append(clauses, "DROP PARTITION ID {"+key+":String}")
	}
	return "ALTER TABLE nebulalog.events " + strings.Join(clauses, ", "), params, nil
}

func retentionStatus(ctx context.Context, conn *pgxpool.Conn, state, message string, extra map[string]any) error {
	if extra == nil {
		extra = map[string]any{}
	}
	extra["state"], extra["message"], extra["observed_at"] = state, message, time.Now().UTC()
	_, err := conn.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention_status'", emergencyJSON(extra))
	return err
}

func retentionActionState(ctx context.Context, conn *pgxpool.Conn, a *RetentionAction, next string, complete bool) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	old := a.State
	copy := *a
	copy.State = next
	if old == "" {
		_, err = tx.Exec(ctx, "INSERT INTO retention_actions(id,state,plan) VALUES($1,$2,$3)", a.ID, next, emergencyJSON(copy))
	} else {
		tag, e := tx.Exec(ctx, "UPDATE retention_actions SET state=$1,plan=$2,updated_at=now(),completed_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE id=$4 AND state=$5 AND completed_at IS NULL", next, emergencyJSON(copy), complete, a.ID, old)
		err = e
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("Retention removal changed concurrently")
		}
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES('retention-controller',$1,'nebulalog.events',$2)", "retention."+next, emergencyJSON(copy)); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err == nil {
		a.State = next
	}
	return err
}

func (s *Store) RetentionStep(ctx context.Context) error {
	return s.retentionStep(ctx, s.CH, time.Now().UTC())
}
func (s *Store) retentionStep(ctx context.Context, ch emergencyClickHouse, now time.Time) error {
	if _, err := s.readHostMaintenance(); err != nil {
		return err
	}
	conn, release, err := emergencyConnection(ctx, s.PG)
	if err != nil {
		return err
	}
	defer release()
	fail := func(e error) error { return errors.Join(e, retentionStatus(ctx, conn, "held", e.Error(), nil)) }
	engine, err := requireRetentionEngine(ctx, conn)
	if err != nil {
		return fail(err)
	}
	if err = verifyRetentionTable(ctx, ch, engine.TableUUID); err != nil {
		return fail(err)
	}
	gate, err := s.effectiveEmergencyMaintenance(ctx, conn)
	if err != nil {
		return fail(err)
	}
	a, err := pendingRetention(ctx, conn)
	if err != nil {
		return fail(err)
	}
	if a != nil {
		switch a.State {
		case "prepared":
			return retentionActionState(ctx, conn, a, "cancelled", true)
		case "executing", "uncertain":
			return retentionStatus(ctx, conn, "uncertain", "Removal outcome is unresolved; no retry, policy change or further removal is permitted", map[string]any{"action_id": a.ID})
		case "awaiting_cleanup":
			measurement, e := observeEmergency(ctx, ch, now)
			if e != nil {
				return fail(e)
			}
			if measurement.Identity != a.Identity {
				return fail(errors.New("Retention cleanup identity changed"))
			}
			_, params, e := retentionDropSQL(a.Partitions)
			if e != nil {
				return fail(e)
			}
			keys := []string{}
			for i := range a.Partitions {
				keys = append(keys, fmt.Sprintf("{retention_partition_%d:String}", i))
			}
			rows, e := ch.Rows(ctx, "SELECT count() AS parts FROM system.parts WHERE database='nebulalog' AND table='events' AND partition_id IN ("+strings.Join(keys, ",")+")", params)
			if e != nil {
				return fail(e)
			}
			if len(rows) != 1 {
				return fail(errors.New("Retention cleanup evidence missing"))
			}
			parts, e := emergencyUint(rows[0], "parts")
			if e != nil {
				return fail(e)
			}
			if parts == 0 {
				if e = retentionActionState(ctx, conn, a, "completed", true); e != nil {
					return e
				}
				return retentionStatus(ctx, conn, "idle", "Acknowledged expired partitions physically cleared; free-space movement is not attributed to this action", nil)
			}
			return retentionStatus(ctx, conn, "awaiting_cleanup", "Removal acknowledged; physical part cleanup is pending. Other partitions may continue receiving logs", map[string]any{"action_id": a.ID, "remaining_parts": parts, "partition_count": len(a.Partitions)})
		default:
			return fail(errors.New("Unsupported retention removal state"))
		}
	}
	if gate.Held {
		return retentionStatus(ctx, conn, "maintenance", "Host maintenance holds new normal-retention removals", nil)
	}
	emergency, err := pendingEmergency(ctx, conn)
	if err != nil {
		return fail(err)
	}
	state, err := readEmergencyStatus(ctx, conn)
	if err != nil {
		return fail(err)
	}
	if emergency != nil || state.Active {
		return retentionStatus(ctx, conn, "emergency", "Emergency storage protection has priority", nil)
	}
	p, err := readRetention(ctx, conn)
	if err != nil {
		return fail(err)
	}
	measurement, err := observeEmergency(ctx, ch, now)
	if err != nil {
		return fail(err)
	}
	if state.Identity == nil || *state.Identity != measurement.Identity || measurement.Identity.TableUUID != engine.TableUUID {
		return fail(errors.New("Retention storage identity is unverified or changed"))
	}
	emergencyPolicy, err := readEmergencyPolicy(ctx, conn)
	if err != nil {
		return fail(err)
	}
	if emergencyPolicy.Enabled && measurement.UsedPercent >= float64(emergencyPolicy.TriggerPercent) {
		return retentionStatus(ctx, conn, "emergency", "Emergency threshold reached; normal expiry waits for storage protection", nil)
	}
	excluded, _, err := insertionExclusions(ctx, conn, measurement.Identity)
	if err != nil {
		return fail(err)
	}
	groups, err := inspectPartitionGroups(ctx, ch)
	if err != nil {
		return fail(err)
	}
	eligible, err := eligibleRetentionPartitions(groups, p, now)
	if err != nil {
		return fail(err)
	}
	selected := []EmergencyPartition{}
	for _, c := range eligible {
		if !excluded[emergencyInsertPartition{c.LogType, c.PartitionDay}] {
			selected = append(selected, c)
		}
		if len(selected) == retentionPartitionBatch {
			break
		}
	}
	if len(selected) == 0 {
		return retentionStatus(ctx, conn, "idle", "No complete expired day is eligible; boundary days and uncertain insertions are retained", map[string]any{"eligible_partition_count": len(eligible)})
	}
	// Metadata only: the verified category/day partition key proves every row's
	// ingestion age. Unlike emergency cleanup, normal expiry includes parse errors
	// and unknown physical categories, using the administrator's global fallback.
	latest, err := observeEmergency(ctx, ch, now)
	if err != nil {
		return fail(err)
	}
	if latest.Identity != measurement.Identity {
		return fail(errors.New("Retention pre-dispatch identity changed"))
	}
	current, err := inspectPartitionGroups(ctx, ch)
	if err != nil {
		return fail(err)
	}
	currentEligible, err := eligibleRetentionPartitions(current, p, now)
	if err != nil {
		return fail(err)
	}
	for _, want := range selected {
		matched := false
		for _, got := range currentEligible {
			matched = matched || sameEmergencyPlan(got, want)
		}
		if !matched {
			return retentionStatus(ctx, conn, "changed", "Partition changed during planning; no removal dispatched", nil)
		}
	}
	a = &RetentionAction{ID: emergencyID(), QueryID: emergencyID(), Policy: p, At: now, Identity: latest.Identity, Partitions: selected}
	sql, params, err := retentionDropSQL(selected)
	if err != nil {
		return fail(err)
	}
	if err = retentionActionState(ctx, conn, a, "prepared", false); err != nil {
		return err
	}
	if err = retentionActionState(ctx, conn, a, "executing", false); err != nil {
		return err
	}
	if err = conn.Ping(ctx); err != nil {
		return err
	}
	if err = ch.ExecWithQueryID(ctx, sql, params, a.QueryID); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return errors.Join(err, retentionActionState(cleanup, conn, a, "uncertain", false))
	}
	if err = retentionActionState(ctx, conn, a, "awaiting_cleanup", false); err != nil {
		return err
	}
	return retentionStatus(ctx, conn, "awaiting_cleanup", "Expired partition batch acknowledged; physical cleanup remains pending", map[string]any{"action_id": a.ID, "partition_count": len(selected), "eligible_partition_count": len(eligible)})
}
