package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRetentionPolicyPhysicalAliasesAndLegacyMeaning(t *testing.T) {
	old, err := decodeRetention([]byte(`{"global_days":90,"per_type":{"alarms":7,"system":365,"dns":30}}`))
	if err != nil || old.Revision != 1 || old.Days("alarms") != 365 || old.LegacyAlarmsDays == nil || *old.LegacyAlarmsDays != 7 {
		t.Fatal(old, err)
	}
	for _, days := range []int{30, 60, 90, 180, 365, 1, 123, 3650} {
		p, err := CanonicalRetention(Retention{Revision: 2, GlobalDays: days, PerType: map[string]int{"alarms": 7, "dns": 30, "threat": 365}})
		if err != nil || p.Days("system") != 7 || p.Days("alarms") != 7 || p.Days("dns") != 30 || p.Days("threat") != 365 || p.Days("unknown") != days {
			t.Fatal(p, err)
		}
		if _, ok := p.PerType["alarms"]; ok {
			t.Fatal("virtual category persisted")
		}
	}
	for _, p := range []Retention{
		{Revision: 1, GlobalDays: 0}, {Revision: 1, GlobalDays: 3651}, {GlobalDays: 30},
		{Revision: 1, GlobalDays: 30, PerType: map[string]int{"unified": 30}},
		{Revision: 1, GlobalDays: 30, PerType: map[string]int{"parsing": 30}},
		{Revision: 1, GlobalDays: 30, PerType: map[string]int{"system": 30, "alarms": 7}},
		{Revision: 1, GlobalDays: 30, PerType: map[string]int{"traffic": -1}},
	} {
		if _, err := CanonicalRetention(p); err == nil {
			t.Fatal("invalid accepted", p)
		}
	}
}

func TestRetentionPredicateBindsUTCAgeAndPhysicalOverrides(t *testing.T) {
	p := Retention{Revision: 9, GlobalDays: 30, PerType: map[string]int{"system": 365, "dns": 7, "threat": 60}}
	now := time.Date(2026, 10, 19, 23, 59, 59, 123456000, time.FixedZone("west", -7*3600))
	sql, args, err := p.Predicate(now)
	if err != nil {
		t.Fatal(err)
	}
	if args["retention_global"] != "2026-09-20 06:59:59.123456" || args["retention_cutoff_0"] != "2026-10-13 06:59:59.123456" || args["retention_kind_0"] != "dns" || args["retention_kind_1"] != "system" || args["retention_kind_2"] != "threat" {
		t.Fatal(args)
	}
	if !strings.Contains(sql, "ingested_at > {retention_global:DateTime64(6)}") || !strings.Contains(sql, "toDate(ingested_at) >= {retention_global_day:Date}") || !strings.Contains(sql, "log_type NOT IN") || strings.Contains(sql, "expires_at") || strings.Contains(sql, "received_at") || strings.Contains(sql, "2026") {
		t.Fatal(sql)
	}
	again, bound, err := p.Predicate(now.UTC())
	if err != nil || again != sql || !reflect.DeepEqual(bound, args) {
		t.Fatal("nondeterministic predicate")
	}
	p.GlobalDays = 90
	_, extended, _ := p.Predicate(now)
	if extended["retention_global"] >= args["retention_global"] || extended["retention_cutoff_0"] != args["retention_cutoff_0"] {
		t.Fatal("extension rewrites override or shortens fallback")
	}
}

func TestNormalRetentionCompleteDayBoundaryAndNoDiagnosticExemption(t *testing.T) {
	p := Retention{Revision: 1, GlobalDays: 30, PerType: map[string]int{"traffic": 1, "dns": 7, "system": 365}}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	rows := []map[string]any{
		partFixture("traffic", "2026-10-17", strings.Repeat("a", 32)),
		partFixture("traffic", "2026-10-18", strings.Repeat("b", 32)),
		partFixture("unknown", "2020-01-01", strings.Repeat("c", 32)),
		partFixture("system", "2026-10-01", strings.Repeat("d", 32)),
		partFixture("dns", "2026-10-11", strings.Repeat("e", 32)),
	}
	got, err := eligibleRetentionPartitions(rows, p, now)
	if err != nil || len(got) != 3 || got[0].LogType != "unknown" || got[1].LogType != "dns" || got[2].LogType != "traffic" {
		t.Fatal(got, err)
	}
	// A partition represents every parse status; normal policy has no diagnostic
	// exemption. There is no event-row scan to qualify 100 million retained rows.
	if retentionDayExpired(p, "traffic", "2026-10-17", now.Add(-time.Nanosecond)) || !retentionDayExpired(p, "traffic", "2026-10-17", now) || retentionDayExpired(p, "traffic", "bad", now) {
		t.Fatal("whole-day boundary")
	}
	rows[0]["partition"] = "('traffic','2026-10-17') OR 1"
	if _, err = eligibleRetentionPartitions(rows, p, now); err == nil {
		t.Fatal("malformed partition accepted")
	}
}

func TestNormalRetentionBoundAndDelayedInsertionFence(t *testing.T) {
	partitions := []EmergencyPartition{}
	for i := 0; i < retentionPartitionBatch; i++ {
		partitions = append(partitions, EmergencyPartition{PartitionID: fmt.Sprintf("%032x", i+1), LogType: "traffic", PartitionDay: "2020-01-01"})
	}
	sql, params, err := retentionDropSQL(partitions)
	if err != nil || len(params) != 32 || strings.Count(sql, "DROP PARTITION ID") != 32 || strings.Contains(sql, partitions[0].PartitionID) {
		t.Fatal(sql, params, err)
	}
	for _, bad := range [][]EmergencyPartition{nil, append(partitions, partitions[0]), {partitions[0], partitions[0]}, {{PartitionID: "'; DROP TABLE events"}}} {
		if _, _, err := retentionDropSQL(bad); err == nil {
			t.Fatal("unbounded or unsafe drop")
		}
	}
	a := &RetentionAction{State: "uncertain", Partitions: partitions}
	if retentionInsertionFence(a, map[emergencyInsertPartition]bool{{"traffic", "2020-01-01"}: true}) == nil {
		t.Fatal("late insertion raced removal")
	}
	if retentionInsertionFence(a, map[emergencyInsertPartition]bool{{"traffic", "2026-10-19"}: true}) != nil {
		t.Fatal("unrelated day blocked")
	}
}

type migrationCH struct {
	ttl             bool
	id              string
	sql             []string
	stages          []string
	merges          []uint64
	mutations       uint64
	fail            string
	noRemove        bool
	changeAfterStop bool
}

func (f *migrationCH) Rows(_ context.Context, sql string, _ map[string]string) ([]map[string]any, error) {
	if sql == retentionTableSQL {
		id := fixtureTableUUID
		if f.id != "" {
			id = f.id
		}
		ddl := "CREATE TABLE nebulalog.events (ingested_at DateTime64(6)) ENGINE=MergeTree"
		if f.ttl {
			ddl += " TTL expires_at DELETE"
		}
		return []map[string]any{{"uuid": id, "engine": "MergeTree", "partition_key": "(log_type, toDate(ingested_at))", "create_table_query": ddl}}, nil
	}
	if strings.Contains(sql, "system.merges") {
		var m uint64
		if len(f.merges) > 0 {
			m = f.merges[0]
			f.merges = f.merges[1:]
		}
		return []map[string]any{{"merges": m, "mutations": f.mutations}}, nil
	}
	return nil, errors.New("unexpected migration query")
}
func (f *migrationCH) ExecWithQueryID(_ context.Context, sql string, _ map[string]string, id string) error {
	if !emergencyUUID.MatchString(id) {
		return errors.New("missing query trace")
	}
	f.sql = append(f.sql, sql)
	if f.fail == sql {
		return errors.New("lost acknowledgement")
	}
	if sql == "ALTER TABLE nebulalog.events REMOVE TTL" && !f.noRemove {
		f.ttl = false
	}
	if sql == "SYSTEM STOP MERGES nebulalog.events" && f.changeAfterStop {
		f.id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	}
	return nil
}
func (f *migrationCH) stage(value, queryID string) error {
	if !emergencyUUID.MatchString(queryID) {
		return errors.New("missing durable query ID")
	}
	f.stages = append(f.stages, value)
	return nil
}

func TestLegacyTTLTransitionDrainsThenRemovesBeforeActivation(t *testing.T) {
	f := &migrationCH{ttl: true, merges: []uint64{2, 1, 0}}
	if err := removeLegacyRetentionTTL(context.Background(), f, fixtureTableUUID, f.stage); err != nil {
		t.Fatal(err)
	}
	want := []string{"SYSTEM STOP MERGES nebulalog.events", "ALTER TABLE nebulalog.events REMOVE TTL", "SYSTEM START MERGES nebulalog.events"}
	if !reflect.DeepEqual(f.sql, want) || !reflect.DeepEqual(f.stages, []string{"stop-merges-dispatch", "remove-ttl-dispatch", "start-merges-dispatch"}) || f.ttl {
		t.Fatal(f)
	}
	for _, sql := range f.sql {
		if strings.Contains(sql, "MATERIALIZE") || strings.Contains(sql, "UPDATE") || strings.Contains(sql, "DELETE") {
			t.Fatal("row rewrite", sql)
		}
	}
}

func TestLegacyTTLTransitionRefusesMutationChangedIdentityAndAmbiguousDDL(t *testing.T) {
	commands := []string{"SYSTEM STOP MERGES nebulalog.events", "ALTER TABLE nebulalog.events REMOVE TTL", "SYSTEM START MERGES nebulalog.events"}
	for i, command := range commands {
		t.Run(command, func(t *testing.T) {
			f := &migrationCH{ttl: true, fail: command}
			if removeLegacyRetentionTTL(context.Background(), f, fixtureTableUUID, f.stage) == nil || len(f.sql) != i+1 {
				t.Fatal("ambiguous DDL retried or continued", f)
			}
		})
	}
	for _, f := range []*migrationCH{{ttl: true, mutations: 1}, {ttl: true, changeAfterStop: true}, {ttl: true, noRemove: true}} {
		if removeLegacyRetentionTTL(context.Background(), f, fixtureTableUUID, f.stage) == nil {
			t.Fatal("unsafe transition accepted", f)
		}
		for _, sql := range f.sql {
			if strings.Contains(sql, "START MERGES") {
				t.Fatal("unsafe scheduler restart", f)
			}
		}
	}
	f := &migrationCH{ttl: true}
	if removeLegacyRetentionTTL(context.Background(), f, fixtureTableUUID, func(string, string) error { return errors.New("audit unavailable") }) == nil || len(f.sql) != 0 {
		t.Fatal("DDL before durable stage")
	}
	f = &migrationCH{ttl: true, merges: []uint64{1, 1}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if removeLegacyRetentionTTL(ctx, f, fixtureTableUUID, f.stage) == nil || len(f.sql) > 1 {
		t.Fatal("drain cancellation continued")
	}
}
