package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrRetentionRevision = errors.New("Retention changed; refresh before saving")
var ErrRetentionHeld = errors.New("Retention change is held by storage maintenance, migration or an unresolved removal")

type Retention struct {
	Revision   int64          `json:"revision"`
	GlobalDays int            `json:"global_days"`
	PerType    map[string]int `json:"per_type"`
	// Older versions accepted this virtual category but never applied it to
	// stored system events. Show the unused value without silently activating it.
	LegacyAlarmsDays *int `json:"legacy_alarms_days,omitempty"`
}

func (p Retention) Validate() error {
	if p.Revision < 1 || p.GlobalDays < 1 || p.GlobalDays > 3650 || len(p.PerType) > len(emergencyFamilies) {
		return errors.New("Retention requires a revision and 1–3650 whole days")
	}
	for kind, days := range p.PerType {
		known := false
		for _, physical := range emergencyFamilies {
			known = known || kind == physical
		}
		if !known || days < 1 || days > 3650 {
			return errors.New("Invalid physical-category retention policy")
		}
	}
	return nil
}

// CanonicalRetention accepts alarms as an alias only when it is unambiguous.
// The UI edits System (including System alerts) once, never a virtual policy.
func CanonicalRetention(p Retention) (Retention, error) {
	copy := map[string]int{}
	for k, v := range p.PerType {
		copy[k] = v
	}
	p.PerType = copy
	p.LegacyAlarmsDays = nil
	if days, ok := copy["alarms"]; ok {
		if system, exists := copy["system"]; exists && system != days {
			return p, errors.New("System and System alerts share one retention policy; conflicting values are not allowed")
		}
		copy["system"] = days
		delete(copy, "alarms")
	}
	return p, p.Validate()
}

func readRetention(ctx context.Context, q emergencyQuerier) (Retention, error) {
	var raw []byte
	var p Retention
	if err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key='retention'").Scan(&raw); err != nil {
		return p, err
	}
	return decodeRetention(raw)
}

func decodeRetention(raw []byte) (Retention, error) {
	var p Retention
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Revision == 0 {
		p.Revision = 1
	}
	if days, ok := p.PerType["alarms"]; ok {
		p.LegacyAlarmsDays = &days
		delete(p.PerType, "alarms")
	}
	if p.PerType == nil {
		p.PerType = map[string]int{}
	}
	return p, p.Validate()
}

func (s *Store) Retention(ctx context.Context) (Retention, error) { return readRetention(ctx, s.PG) }

func (p Retention) Days(kind string) int {
	if kind == "alarms" {
		kind = "system"
	}
	if days, ok := p.PerType[kind]; ok {
		return days
	}
	return p.GlobalDays
}

// Predicate is constant-size in event count: one clause per physical override,
// plus the global fallback. The explicit date term also prunes day partitions.
// A request captures one policy revision and clock; expiry is ingestion age,
// never the firewall's generated/received timestamp or a new delivery time.
func (p Retention) Predicate(now time.Time) (string, map[string]string, error) {
	if err := p.Validate(); err != nil {
		return "", nil, err
	}
	params := map[string]string{}
	keys := make([]string, 0, len(p.PerType))
	for k := range p.PerType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	clauses, excluded := []string{}, []string{}
	cutoff := func(name string, days int) string {
		t := now.UTC().AddDate(0, 0, -days)
		params[name] = t.Format("2006-01-02 15:04:05.999999")
		params[name+"_day"] = t.Format("2006-01-02")
		return "toDate(ingested_at) >= {" + name + "_day:Date} AND ingested_at > {" + name + ":DateTime64(6)}"
	}
	for i, k := range keys {
		name := "retention_kind_" + strconv.Itoa(i)
		params[name] = k
		excluded = append(excluded, "{"+name+":String}")
		clauses = append(clauses, "(log_type={"+name+":String} AND "+cutoff("retention_cutoff_"+strconv.Itoa(i), p.PerType[k])+")")
	}
	fallback := cutoff("retention_global", p.GlobalDays)
	if len(excluded) > 0 {
		fallback = "log_type NOT IN (" + strings.Join(excluded, ",") + ") AND " + fallback
	}
	clauses = append(clauses, "("+fallback+")")
	return "(" + strings.Join(clauses, " OR ") + ")", params, nil
}

type RetentionEngine struct {
	Schema    int    `json:"schema"`
	Mode      string `json:"mode"`
	TableUUID string `json:"table_uuid,omitempty"`
	Operation string `json:"operation,omitempty"`
	QueryID   string `json:"query_id,omitempty"`
	Message   string `json:"message,omitempty"`
}

func readRetentionEngine(ctx context.Context, q emergencyQuerier) (RetentionEngine, error) {
	var raw []byte
	var v RetentionEngine
	if err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key='retention_engine'").Scan(&raw); err != nil {
		return v, err
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, err
	}
	if v.Schema != 1 {
		return v, errors.New("Unsupported retention engine state")
	}
	return v, nil
}

func (s *Store) RetentionEngine(ctx context.Context) (RetentionEngine, error) {
	return readRetentionEngine(ctx, s.PG)
}

type RetentionView struct {
	Retention
	Engine RetentionEngine `json:"engine"`
	Status map[string]any  `json:"status"`
}

func (s *Store) RetentionView(ctx context.Context) (RetentionView, error) {
	v := RetentionView{}
	var err error
	if v.Retention, err = s.Retention(ctx); err != nil {
		return v, err
	}
	if v.Engine, err = s.RetentionEngine(ctx); err != nil {
		return v, err
	}
	var raw []byte
	if err = s.PG.QueryRow(ctx, "SELECT value FROM settings WHERE key='retention_status'").Scan(&raw); err != nil {
		return v, err
	}
	err = json.Unmarshal(raw, &v.Status)
	return v, err
}

func requireRetentionEngine(ctx context.Context, q emergencyQuerier) (RetentionEngine, error) {
	v, err := readRetentionEngine(ctx, q)
	if err != nil {
		return v, err
	}
	if v.Mode != "partition" || !emergencyUUID.MatchString(v.TableUUID) {
		return v, ErrRetentionHeld
	}
	return v, nil
}

// RetainedPredicate fails closed until the legacy TTL has been removed by the
// explicit migration. A successful policy extension must never leave old TTL
// metadata free to delete rows that the new policy promises to retain.
func (s *Store) RetainedPredicate(ctx context.Context, now time.Time) (Retention, string, map[string]string, error) {
	if _, err := requireRetentionEngine(ctx, s.PG); err != nil {
		return Retention{}, "", nil, err
	}
	p, err := s.Retention(ctx)
	if err != nil {
		return p, "", nil, err
	}
	sql, params, err := p.Predicate(now)
	return p, sql, params, err
}

func (s *Store) UpdateRetention(ctx context.Context, actor string, expected int64, p Retention) (Retention, error) {
	if actor == "" || expected < 1 || expected == int64(^uint64(0)>>1) {
		return p, errors.New("Invalid retention actor or revision")
	}
	p.Revision = expected + 1
	var err error
	if p, err = CanonicalRetention(p); err != nil {
		return p, err
	}
	tx, err := s.PG.Begin(ctx)
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	if err = LockEmergencyPolicy(ctx, tx); err != nil {
		return p, err
	}
	gate, err := s.effectiveEmergencyMaintenance(ctx, tx)
	if err != nil {
		return p, err
	}
	if gate.Held || gate.DeliveryHeld {
		return p, ErrRetentionHeld
	}
	engine, err := requireRetentionEngine(ctx, tx)
	if err != nil {
		return p, err
	}
	if err = verifyRetentionTable(ctx, s.CH, engine.TableUUID); err != nil {
		return p, err
	}
	old, err := readRetention(ctx, tx)
	if err != nil {
		return p, err
	}
	if old.Revision != expected {
		return p, ErrRetentionRevision
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM storage_emergency_actions WHERE completed_at IS NULL) OR EXISTS(SELECT 1 FROM retention_actions WHERE completed_at IS NULL)`).Scan(&pending); err != nil {
		return p, err
	}
	if pending {
		return p, ErrRetentionHeld
	}
	if _, err = tx.Exec(ctx, "UPDATE settings SET value=$1 WHERE key='retention'", emergencyJSON(p)); err != nil {
		return p, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor,action,target,detail) VALUES($1,'retention.update','all-retained-and-future',$2)", actor, emergencyJSON(map[string]any{"before": old, "after": p, "scope": "all-retained-and-future", "age": "ingested_at", "deleted_data_restored": false})); err != nil {
		return p, err
	}
	return p, tx.Commit(ctx)
}
