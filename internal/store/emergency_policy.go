package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// One database-scoped coordination lock is shared by policy changes, delivery
// and the controller. Durable unresolved actions also fence after lock loss.
const EmergencyLockID int64 = 4850182995969828167
const EmergencyObservationMaxAge = 2 * time.Minute

var ErrEmergencyRevision = errors.New("Emergency policy changed; refresh before saving")
var ErrEmergencyPending = errors.New("An emergency removal is unresolved; policy changes are held")
var ErrStoragePressure = errors.New("Storage protection is holding delivery; durable spool is retained")

var emergencyFamilies = []string{"traffic", "url", "threat", "wildfire", "dns", "data", "hip", "globalprotect", "iptag", "userid", "decryption", "tunnel", "configuration", "system", "authentication"}

type EmergencyPolicy struct {
	Revision       int64          `json:"revision"`
	Enabled        bool           `json:"enabled"`
	TriggerPercent int            `json:"trigger_percent"`
	RecoverPercent int            `json:"recover_percent"`
	MinimumDays    map[string]int `json:"minimum_days"`
}

func DefaultEmergencyPolicy() EmergencyPolicy {
	p := EmergencyPolicy{Revision: 1, Enabled: true, TriggerPercent: 95, RecoverPercent: 90, MinimumDays: map[string]int{}}
	for _, family := range emergencyFamilies {
		p.MinimumDays[family] = 30
	}
	p.MinimumDays["traffic"], p.MinimumDays["url"] = 1, 7
	return p
}

func (p EmergencyPolicy) Validate() error {
	if p.Revision < 1 || p.TriggerPercent < 90 || p.TriggerPercent > 99 || p.RecoverPercent < 70 || p.RecoverPercent >= p.TriggerPercent || len(p.MinimumDays) != len(emergencyFamilies) {
		return errors.New("Emergency policy requires trigger 90–99%, recovery 70% to below trigger, and every supported category minimum")
	}
	for _, family := range emergencyFamilies {
		if p.MinimumDays[family] < 1 || p.MinimumDays[family] > 3650 {
			return errors.New("Emergency minimum ages must be whole days from 1 to 3650; unknown categories cannot be added")
		}
	}
	return nil
}

type EmergencyStatus struct {
	MaintenanceHeld      bool             `json:"maintenance_held"`
	DeliveryHeld         bool             `json:"delivery_held"`
	MaintenanceOperation *string          `json:"maintenance_operation,omitempty"`
	MaintenanceMessage   string           `json:"maintenance_message,omitempty"`
	State                string           `json:"state"`
	ObservedAt           *time.Time       `json:"observed_at"`
	Message              string           `json:"message"`
	UsedPercent          *float64         `json:"used_percent,omitempty"`
	Pending              *EmergencyAction `json:"pending,omitempty"`
	// Persist hysteresis and initial identity; neither is inferred from a badge.
	Active           bool               `json:"emergency_active"`
	InsertExclusions int                `json:"insert_exclusions"`
	ExclusionMessage string             `json:"exclusion_message,omitempty"`
	Identity         *EmergencyIdentity `json:"identity,omitempty"`
}

type EmergencyView struct {
	Policy        EmergencyPolicy   `json:"policy"`
	Status        EmergencyStatus   `json:"status"`
	RecentActions []EmergencyAction `json:"recent_actions"`
}

type emergencyQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readEmergencyPolicy(ctx context.Context, q emergencyQuerier) (EmergencyPolicy, error) {
	var raw []byte
	var p EmergencyPolicy
	if err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key='storage_emergency'").Scan(&raw); err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

func readEmergencyStatus(ctx context.Context, q emergencyQuerier) (EmergencyStatus, error) {
	var raw []byte
	var state EmergencyStatus
	if err := q.QueryRow(ctx, "SELECT value FROM storage_emergency_state WHERE singleton=true").Scan(&raw); err != nil {
		return state, err
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	return state, nil
}

func (s *Store) Emergency(ctx context.Context) (EmergencyView, error) {
	v := EmergencyView{RecentActions: []EmergencyAction{}}
	var err error
	if v.Policy, err = readEmergencyPolicy(ctx, s.PG); err != nil {
		return v, err
	}
	if v.Status, err = readEmergencyStatus(ctx, s.PG); err != nil {
		return v, err
	}
	gate, err := s.effectiveEmergencyMaintenance(ctx, s.PG)
	if err != nil {
		return v, err
	}
	v.Status.maintenance(gate)
	rows, err := s.PG.Query(ctx, "SELECT id::text,state,created_at,updated_at,plan,message FROM storage_emergency_actions ORDER BY created_at DESC,id DESC LIMIT 20")
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var a EmergencyAction
		var raw []byte
		if err = rows.Scan(&a.ID, &a.State, &a.CreatedAt, &a.UpdatedAt, &raw, &a.Message); err != nil {
			return v, err
		}
		if err = json.Unmarshal(raw, &a.EmergencyPlan); err != nil {
			return v, err
		}
		v.RecentActions = append(v.RecentActions, a)
	}
	return v, rows.Err()
}

// LockEmergencyPolicy must also surround normal TTL policy writes so planning
// observes one coherent policy generation while a destructive intent is made.
func LockEmergencyPolicy(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", EmergencyLockID)
	return err
}

func (s *Store) UpdateEmergencyPolicy(ctx context.Context, actor string, expected int64, p EmergencyPolicy) error {
	p.Revision = expected + 1
	if expected < 1 || p.Revision <= expected || actor == "" {
		return errors.New("Invalid emergency policy revision or actor")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	tx, err := s.PG.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = LockEmergencyPolicy(ctx, tx); err != nil {
		return err
	}
	old, err := readEmergencyPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if old.Revision != expected {
		return ErrEmergencyRevision
	}
	var pending bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM storage_emergency_actions WHERE completed_at IS NULL) OR EXISTS(SELECT 1 FROM retention_actions WHERE completed_at IS NULL)").Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrEmergencyPending
	}
	raw, _ := json.Marshal(p)
	evidence, _ := json.Marshal(map[string]any{"before": old, "after": p})
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,'storage.emergency.policy','nebulalog.events',$2)", actor, evidence); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='storage_emergency'", raw); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func emergencyConnection(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Conn, func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	var acquired bool
	if err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", EmergencyLockID).Scan(&acquired); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn.Hijack().Close(cleanup)
		return nil, nil, err
	}
	if !acquired {
		conn.Release()
		return nil, nil, fmt.Errorf("storage protection worker is already active")
	}
	return conn, func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var released bool
		if err := conn.QueryRow(cleanup, "SELECT pg_advisory_unlock($1)", EmergencyLockID).Scan(&released); err != nil || !released {
			conn.Hijack().Close(cleanup)
		} else {
			conn.Release()
		}
	}, nil
}
