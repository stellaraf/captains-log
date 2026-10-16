package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func emergencyID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func pendingEmergency(ctx context.Context, q emergencyQuerier) (*EmergencyAction, error) {
	var a EmergencyAction
	var raw []byte
	err := q.QueryRow(ctx, "SELECT id::text,state,created_at,updated_at,plan,message FROM storage_emergency_actions WHERE completed_at IS NULL").Scan(&a.ID, &a.State, &a.CreatedAt, &a.UpdatedAt, &raw, &a.Message)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &a.EmergencyPlan); err != nil {
		return nil, err
	}
	if !emergencyUUID.MatchString(a.ID) || !emergencyUUID.MatchString(a.QueryID) || !emergencyPartitionID.MatchString(a.PartitionID) || a.PolicyRevision != a.Policy.Revision || a.Policy.Validate() != nil || a.TableUUID != a.Before.Identity.TableUUID || a.Rows == 0 || len(a.Parts) == 0 {
		return nil, errors.New("invalid retained emergency intent")
	}
	return &a, nil
}

func writeEmergencyState(ctx context.Context, conn *pgxpool.Conn, state EmergencyStatus) error {
	tag, err := conn.Exec(ctx, "UPDATE storage_emergency_state SET value=$1 WHERE singleton=true", emergencyJSON(state))
	if err == nil && tag.RowsAffected() != 1 {
		return errors.New("storage protection state missing")
	}
	return err
}

// State and audit records commit together. If commit outcome is unknown, the
// durable action is left unresolved and must not be replayed by another worker.
func actionEmergency(ctx context.Context, conn *pgxpool.Conn, a *EmergencyAction, next, message string, state EmergencyStatus, complete bool) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var tag int64
	if a.State == "" {
		result, e := tx.Exec(ctx, "INSERT INTO storage_emergency_actions(id,state,plan,message) VALUES($1,$2,$3,$4)", a.ID, next, emergencyJSON(a.EmergencyPlan), message)
		err = e
		tag = result.RowsAffected()
	} else {
		result, e := tx.Exec(ctx, "UPDATE storage_emergency_actions SET state=$1,message=$2,updated_at=now(),completed_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE id=$4 AND state=$5 AND completed_at IS NULL", next, message, complete, a.ID, a.State)
		err = e
		tag = result.RowsAffected()
	}
	if err != nil {
		return err
	}
	if tag != 1 {
		return errors.New("emergency action changed concurrently")
	}
	evidence := map[string]any{"id": a.ID, "before_state": a.State, "state": next, "plan": a.EmergencyPlan, "message": message, "observation": state}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES('storage-controller',$1,$2,$3)", "storage.emergency."+next, a.PartitionID, emergencyJSON(evidence)); err != nil {
		return err
	}
	copy := *a
	copy.State = next
	copy.Message = message
	state.Pending = &copy
	if complete {
		state.Pending = nil
	}
	if _, err = tx.Exec(ctx, "UPDATE storage_emergency_state SET value=$1 WHERE singleton=true", emergencyJSON(state)); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err == nil {
		a.State = next
		a.Message = message
	}
	return err
}

type emergencyInsertPartition struct {
	LogType string `json:"log_type"`
	Day     string `json:"day"`
}

func insertionExclusions(ctx context.Context, conn *pgxpool.Conn, identity EmergencyIdentity) (map[emergencyInsertPartition]bool, int, error) {
	rows, err := conn.Query(ctx, "SELECT table_uuid::text,partitions FROM storage_emergency_inserts ORDER BY created_at,id LIMIT 4097")
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	excluded := map[emergencyInsertPartition]bool{}
	count := 0
	for rows.Next() {
		count++
		if count > 4096 {
			return nil, count, errors.New("in-flight insertion evidence exceeds limit")
		}
		var table string
		var raw []byte
		if err = rows.Scan(&table, &raw); err != nil {
			return nil, count, err
		}
		if table != identity.TableUUID {
			return nil, count, errors.New("in-flight insertion references a different table; recovery required")
		}
		var partitions []emergencyInsertPartition
		if err = json.Unmarshal(raw, &partitions); err != nil || len(partitions) == 0 || len(partitions) > 10000 {
			return nil, count, errors.New("invalid in-flight insertion partition evidence")
		}
		for _, p := range partitions {
			if p.LogType == "" {
				return nil, count, errors.New("invalid insertion category")
			}
			if _, err = time.Parse("2006-01-02", p.Day); err != nil {
				return nil, count, err
			}
			excluded[p] = true
		}
	}
	return excluded, count, rows.Err()
}

// EmergencyStep does at most one destructive request. Runtime observations and
// unresolved intent survive restarts; no timeout or lost response is retried.
func (s *Store) EmergencyStep(ctx context.Context) error {
	return s.emergencyStep(ctx, s.CH, time.Now().UTC())
}
func (s *Store) emergencyStep(ctx context.Context, ch emergencyClickHouse, now time.Time) error {
	if _, err := s.readHostMaintenance(); err != nil {
		return err
	}
	conn, release, err := emergencyConnection(ctx, s.PG)
	if err != nil {
		return err
	}
	defer release()
	state, err := readEmergencyStatus(ctx, conn)
	if err != nil {
		return err
	}
	fail := func(reason string, cause error) error {
		state.State = "unavailable"
		state.Message = reason
		state.ObservedAt = &now
		state.UsedPercent = nil
		save := writeEmergencyState(ctx, conn, state)
		return errors.Join(cause, save)
	}
	policy, err := readEmergencyPolicy(ctx, conn)
	if err != nil {
		return fail("Policy unavailable; deletion and delivery are held", err)
	}
	gate, err := s.effectiveEmergencyMaintenance(ctx, conn)
	if err != nil {
		return fail("Host maintenance gate unavailable; deletion and delivery are held", err)
	}
	state.maintenance(gate)
	pending, err := pendingEmergency(ctx, conn)
	if err != nil {
		return fail("Action evidence unavailable; deletion and delivery are held", err)
	}
	state.Pending = pending
	measurement, err := observeEmergency(ctx, ch, now)
	if err != nil {
		return fail("ClickHouse disk or table identity unavailable; deletion and delivery are held", err)
	}
	state.ObservedAt = &now
	state.UsedPercent = &measurement.UsedPercent
	if state.Identity == nil {
		// This first observation is the durable identity root; replacement requires
		// an explicit operator migration, never silent automatic adoption.
		tx, e := conn.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		state.Identity = &measurement.Identity
		if _, e = tx.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES('storage-controller','storage.emergency.identity','nebulalog.events',$1)", emergencyJSON(measurement)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE storage_emergency_state SET value=$1 WHERE singleton=true", emergencyJSON(state)); e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
	} else if *state.Identity != measurement.Identity {
		return fail("ClickHouse table or disk identity changed; operator recovery required", errors.New("storage identity changed"))
	}
	excluded, count, err := insertionExclusions(ctx, conn, measurement.Identity)
	if err != nil {
		return fail("Insertion evidence cannot be verified; operator recovery required", err)
	}
	state.InsertExclusions = count
	state.ExclusionMessage = ""
	if count > 0 {
		state.ExclusionMessage = "Unacknowledged insert attempts exclude affected partitions from emergency removal; operator review may be required"
	}
	if pending != nil {
		state.Active = true
		switch pending.State {
		case "prepared":
			state.State = "emergency"
			state.Message = "Cancelled an interrupted intent that was never authorized for dispatch; next observation replans"
			return actionEmergency(ctx, conn, pending, "cancelled", state.Message, state, true)
		case "executing", "uncertain":
			state.State = "blocked"
			state.Message = "Removal outcome is uncertain; operator recovery required. No retry, further removal, policy change or WAL delivery is permitted"
			return writeEmergencyState(ctx, conn, state)
		case "awaiting_cleanup":
			state.State = "awaiting_cleanup"
			state.Message = "Successful removal acknowledged; waiting for all active and inactive parts to disappear and a positive free-space observation"
			if pending.Before.Identity != measurement.Identity {
				return fail("Pending removal identity changed; operator recovery required", errors.New("pending identity mismatch"))
			}
			rows, e := ch.Rows(ctx, "SELECT count() AS parts FROM system.parts WHERE database='nebulalog' AND table='events' AND partition_id={partition:String}", map[string]string{"partition": pending.PartitionID})
			if e != nil {
				return fail("Physical cleanup observation unavailable; delivery remains held", e)
			}
			if len(rows) != 1 {
				return fail("Physical cleanup observation unavailable", errors.New("invalid cleanup result"))
			}
			parts, e := emergencyUint(rows[0], "parts")
			if e != nil {
				return fail("Physical cleanup observation invalid", e)
			}
			if parts == 0 && measurement.Free > pending.Before.Free {
				state.State = "emergency"
				state.Message = "Acknowledged removal physically cleared; capacity will be evaluated before any next removal"
				// Measured free-space movement is evidence, never attributed bytes reclaimed.
				return actionEmergency(ctx, conn, pending, "completed", state.Message, state, true)
			}
			if parts == 0 && now.Sub(pending.UpdatedAt) > 2*time.Minute {
				state.State = "blocked"
				state.Message = "Removal is acknowledged and its parts are gone, but no net free-space gain is observed; concurrent usage may mask reclamation. Further deletion and delivery remain held for capacity/operator review"
			}
			if parts > 0 && now.Sub(pending.UpdatedAt) > 30*time.Minute {
				state.State = "blocked"
				state.Message = "Acknowledged removal has not physically cleared after 30 minutes; inspect active readers and ClickHouse cleanup. Further deletion and delivery remain held"
			}
			return writeEmergencyState(ctx, conn, state)
		default:
			return fail("Unsupported pending action; operator recovery required", errors.New("invalid pending state"))
		}
	}
	if !policy.Enabled {
		state.State = "disabled"
		state.Active = false
		state.Message = "Automatic emergency removal disabled; normal expiry and bounded spooling remain active"
		return writeEmergencyState(ctx, conn, state)
	}
	state.Active = state.Active || measurement.UsedPercent >= float64(policy.TriggerPercent)
	if state.Active && measurement.UsedPercent <= float64(policy.RecoverPercent) {
		state.Active = false
	}
	if !state.Active {
		state.State = "normal"
		state.Message = "ClickHouse usable data-disk capacity is below the active emergency threshold"
		return writeEmergencyState(ctx, conn, state)
	}
	if gate.Held {
		state.State = "blocked"
		state.Message = "Emergency capacity pressure is present, but host lifecycle maintenance prohibits new removals; delivery remains held"
		return writeEmergencyState(ctx, conn, state)
	}
	state.State = "emergency"
	state.Message = "Emergency active; selecting one eligible complete partition"
	candidates, err := inspectEmergencyPartitions(ctx, ch, policy, now)
	if err != nil {
		return fail("Partition evidence unavailable; no deletion authorized", err)
	}
	var selected *EmergencyPartition
	// Bound expensive diagnostic checks per cycle; fail closed rather than skip
	// unexamined Traffic partitions in favor of another category.
	for i, c := range candidates {
		if i >= 128 {
			break
		}
		if excluded[emergencyInsertPartition{c.LogType, c.PartitionDay}] {
			continue
		}
		ok, e := verifyEmergencyRows(ctx, ch, c)
		if e != nil {
			return fail("Partition row protection proof unavailable", e)
		}
		if ok {
			copy := c
			selected = &copy
			break
		}
	}
	if selected == nil {
		state.State = "blocked"
		state.Message = "No eligible partition is proven safe: minimum ages, diagnostics, insertion exclusions or bounded inspection prevent removal; WAL delivery is held"
		return writeEmergencyState(ctx, conn, state)
	}
	// A second exact observation is required under the exclusive application
	// fence. Privileged external DDL is not authorized by this application lock.
	latest, err := observeEmergency(ctx, ch, now)
	if err != nil || latest.Identity != measurement.Identity {
		return fail("Pre-dispatch table identity changed or unavailable", errors.Join(err, errors.New("identity recheck failed")))
	}
	if latest.UsedPercent <= float64(policy.RecoverPercent) {
		state.Active = false
		state.State = "normal"
		state.UsedPercent = &latest.UsedPercent
		state.Message = "Capacity recovered during planning; no removal authorized"
		return writeEmergencyState(ctx, conn, state)
	}
	current, err := inspectEmergencyPartitions(ctx, ch, policy, now)
	if err != nil {
		return fail("Pre-dispatch partition evidence unavailable", err)
	}
	matched := false
	for _, c := range current {
		if sameEmergencyPlan(c, *selected) {
			matched = true
			break
		}
	}
	if !matched {
		state.Message = "Partition changed during planning; no deletion authorized until a fresh observation"
		return writeEmergencyState(ctx, conn, state)
	}
	safe, err := verifyEmergencyRows(ctx, ch, *selected)
	if err != nil {
		return fail("Pre-dispatch protection proof unavailable", err)
	}
	if !safe {
		state.Message = "Partition gained protected or changed rows; no deletion authorized"
		return writeEmergencyState(ctx, conn, state)
	}
	a := &EmergencyAction{ID: emergencyID(), EmergencyPlan: EmergencyPlan{EmergencyPartition: *selected, PolicyRevision: policy.Revision, Policy: policy, TableUUID: measurement.Identity.TableUUID, Before: latest, QueryID: emergencyID()}}
	if err = actionEmergency(ctx, conn, a, "prepared", "Exact policy, table, partition and part estimates durably authorized", state, false); err != nil {
		return err
	}
	if err = actionEmergency(ctx, conn, a, "executing", "Single destructive query dispatch authorized; any ambiguous outcome remains held", state, false); err != nil {
		return err
	}
	// Do not reconnect or transfer this attempt if the PG lock session was lost.
	if err = conn.Ping(ctx); err != nil {
		return err
	}
	err = ch.ExecWithQueryID(ctx, "ALTER TABLE nebulalog.events DROP PARTITION ID {partition:String}", map[string]string{"partition": a.PartitionID}, a.QueryID)
	if err != nil {
		state.State = "blocked"
		state.Message = "Removal response is uncertain; operator recovery required; this query is never retried"
		saveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return errors.Join(err, actionEmergency(saveCtx, conn, a, "uncertain", state.Message, state, false))
	}
	state.State = "awaiting_cleanup"
	state.Message = "Server acknowledged removal; physical cleanup must finish before any further removal or delivery"
	return actionEmergency(ctx, conn, a, "awaiting_cleanup", state.Message, state, false)
}

// RunEmergencyRetention is safe with multiple application roles: a database
// advisory lock chooses one observer, and the committed global intent fences
// destruction even if that lock connection is lost.
func (s *Store) RunEmergencyRetention(ctx context.Context) {
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := s.EmergencyStep(attempt)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("emergency storage observation held", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
