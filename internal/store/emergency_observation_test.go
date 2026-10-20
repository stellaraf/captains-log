package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Only observations are injected. The opt-in controller test below uses the
// real PostgreSQL state/audit transaction and the existing isolated fixture.
type emergencyObservationCH struct {
	base                 *emergencyFake
	tables, disks, other int
	edit                 func(string, int, []map[string]any) error
}

func (c *emergencyObservationCH) Rows(ctx context.Context, sql string, params map[string]string) ([]map[string]any, error) {
	kind, count := "other", 0
	switch {
	case strings.Contains(sql, "system.tables"):
		c.tables++
		kind, count = "table", c.tables
	case strings.Contains(sql, "system.disks"):
		c.disks++
		kind, count = "disk", c.disks
	default:
		c.other++
		count = c.other
	}
	rows, err := c.base.Rows(ctx, sql, params)
	if err == nil && c.edit != nil {
		err = c.edit(kind, count, rows)
	}
	return rows, err
}

func (c *emergencyObservationCH) ExecWithQueryID(ctx context.Context, sql string, params map[string]string, id string) error {
	return c.base.ExecWithQueryID(ctx, sql, params, id)
}

func TestEmergencyObservationResamples(t *testing.T) {
	for _, succeedAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("coherent sample %d", succeedAt), func(t *testing.T) {
			ch := &emergencyObservationCH{base: fakeEmergency()}
			ch.edit = func(kind string, count int, rows []map[string]any) error {
				if kind == "disk" {
					rows[0]["free_space"] = 100
					rows[0]["unreserved_space"] = 200
					if count == succeedAt {
						rows[0]["free_space"] = 3000
						rows[0]["unreserved_space"] = 2000
					}
				}
				return nil
			}
			now := time.Date(2026, 10, 16, 5, 0, 0, 123, time.FixedZone("fixture", -7*60*60))
			m, err := observeEmergency(context.Background(), ch, now)
			if err != nil {
				t.Fatal(err)
			}
			if ch.tables != succeedAt || ch.disks != succeedAt || ch.other != 0 || ch.base.calls != 0 {
				t.Fatalf("unexpected reads/effects: %+v", ch)
			}
			if m.Free != 3000 || m.Unreserved != 2000 || m.Available != 2000 || m.UsedPercent != 80 || m.KeepFree != 1000 || m.Identity.TableUUID != fixtureTableUUID || m.ObservedAt != now.UTC() {
				t.Fatalf("did not return only the coherent sample: %+v", m)
			}
		})
	}
}

func TestEmergencyObservationExhaustsThreeSamples(t *testing.T) {
	ch := &emergencyObservationCH{base: fakeEmergency()}
	ch.edit = func(kind string, count int, rows []map[string]any) error {
		if kind == "disk" {
			rows[0]["free_space"] = 100 + count
			rows[0]["unreserved_space"] = 200 + count
		}
		return nil
	}
	m, err := observeEmergency(context.Background(), ch, time.Now())
	if err == nil || !strings.Contains(err.Error(), "inconsistent disk capacity observation") || ch.tables != 3 || ch.disks != 3 || ch.other != 0 || ch.base.calls != 0 {
		t.Fatalf("unbounded or accepted observation: %+v, %v", ch, err)
	}
	if m.Available != 0 || m.UsedPercent != 0 {
		t.Fatalf("rejected tuple acquired usable capacity: %+v", m)
	}
	for i := 1; i <= 3; i++ {
		want := fmt.Sprintf("Capacity:10000 Free:%d Unreserved:%d KeepFree:1000", 100+i, 200+i)
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("lost sample %d: %v", i, err)
		}
	}
}

func TestEmergencyObservationPinsIdentityAcrossRetries(t *testing.T) {
	for _, field := range []string{"uuid", "data_path", "disk_path", "engine"} {
		t.Run(field, func(t *testing.T) {
			ch := &emergencyObservationCH{base: fakeEmergency()}
			ch.edit = func(kind string, count int, rows []map[string]any) error {
				if kind == "disk" && count == 1 {
					rows[0]["unreserved_space"] = 600
				}
				if count != 2 {
					return nil
				}
				if kind == "table" {
					switch field {
					case "uuid":
						id := "22345678-1234-4234-8234-123456789abc"
						rows[0]["uuid"] = id
						rows[0]["data_paths"] = []any{"/var/lib/clickhouse/store/223/" + id + "/"}
					case "data_path":
						rows[0]["data_paths"] = []any{"/var/lib/clickhouse/store/456/" + fixtureTableUUID + "/"}
					case "engine":
						rows[0]["engine"] = "ReplicatedMergeTree"
					}
				}
				if kind == "disk" && field == "disk_path" {
					rows[0]["path"] = "/different/"
				}
				return nil
			}
			_, err := observeEmergency(context.Background(), ch, time.Now())
			if err == nil || ch.tables != 2 || ch.disks > 2 || !strings.Contains(err.Error(), "Capacity:10000 Free:500 Unreserved:600 KeepFree:1000") {
				t.Fatalf("changed identity accepted or earlier evidence lost: %+v, %v", ch, err)
			}
			if (field == "uuid" || field == "data_path") && !strings.Contains(err.Error(), "identity changed") {
				t.Fatalf("individually valid changed identity was not pinned: %v", err)
			}
		})
	}
}

func TestEmergencyObservationDoesNotRetryOtherInvalidSamples(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"zero capacity", func(r map[string]any) { r["total_space"] = 0 }},
		{"free over capacity", func(r map[string]any) { r["free_space"] = 10001 }},
		{"unreserved over capacity", func(r map[string]any) { r["unreserved_space"] = 10001 }},
		{"both over capacity", func(r map[string]any) { r["free_space"], r["unreserved_space"] = 10001, 10002 }},
		{"missing scalar", func(r map[string]any) { delete(r, "free_space") }},
		{"negative scalar", func(r map[string]any) { r["free_space"] = -1 }},
		{"overflow scalar", func(r map[string]any) { r["free_space"] = "18446744073709551616" }},
		{"fractional scalar", func(r map[string]any) { r["free_space"] = 1.5 }},
		{"read only", func(r map[string]any) { r["is_read_only"] = 1 }},
		{"remote", func(r map[string]any) { r["is_remote"] = 1 }},
	}
	for _, key := range []string{"total_space", "free_space", "unreserved_space", "keep_free_space", "is_read_only", "is_remote"} {
		cases = append(cases, struct {
			name string
			edit func(map[string]any)
		}{"malformed " + key, func(r map[string]any) { r[key] = "invalid" }})
	}
	for _, tc := range cases {
		// Invalid evidence must stop immediately even after a prior retryable
		// tuple. In particular, malformed reserve/flags cannot hide behind it.
		for _, failAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s sample %d", tc.name, failAt), func(t *testing.T) {
				ch := &emergencyObservationCH{base: fakeEmergency()}
				ch.edit = func(kind string, count int, rows []map[string]any) error {
					if kind == "disk" {
						rows[0]["unreserved_space"] = 600
						if count == failAt {
							tc.edit(rows[0])
						}
					}
					return nil
				}
				_, err := observeEmergency(context.Background(), ch, time.Now())
				if err == nil || ch.tables != failAt || ch.disks != failAt {
					t.Fatalf("invalid evidence retried/accepted: %+v, %v", ch, err)
				}
				if failAt == 2 && !strings.Contains(err.Error(), "Capacity:10000 Free:500 Unreserved:600 KeepFree:1000") {
					t.Fatalf("lost prior rejected tuple: %v", err)
				}
			})
		}
	}
}

func TestEmergencyObservationReadErrorsDoNotRetry(t *testing.T) {
	readErr := errors.New("fixture read failed")
	for _, kind := range []string{"table", "disk"} {
		for _, failAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s sample %d", kind, failAt), func(t *testing.T) {
				ch := &emergencyObservationCH{base: fakeEmergency()}
				ch.edit = func(got string, count int, rows []map[string]any) error {
					if got == kind && count == failAt {
						return readErr
					}
					if got == "disk" {
						rows[0]["unreserved_space"] = 600
					}
					return nil
				}
				_, err := observeEmergency(context.Background(), ch, time.Now())
				wantDisks := failAt
				if kind == "table" {
					wantDisks--
				}
				if !errors.Is(err, readErr) || ch.tables != failAt || ch.disks != wantDisks {
					t.Fatalf("read error retried/lost: %+v, %v", ch, err)
				}
				if failAt == 2 && !strings.Contains(err.Error(), "Capacity:10000 Free:500 Unreserved:600 KeepFree:1000") {
					t.Fatalf("lost rejected tuple on read failure: %v", err)
				}
			})
		}
	}
}

func TestEmergencyObservationCancellationStopsReads(t *testing.T) {
	for _, boundary := range []string{"before first read", "after table read", "after rejected disk", "after coherent disk"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := &emergencyObservationCH{base: fakeEmergency()}
			if boundary == "before first read" {
				cancel()
			}
			ch.edit = func(kind string, _ int, rows []map[string]any) error {
				if kind == "table" && boundary == "after table read" {
					cancel()
				}
				if kind == "disk" {
					if boundary == "after rejected disk" {
						rows[0]["unreserved_space"] = 600
					}
					cancel()
				}
				return nil
			}
			_, err := observeEmergency(ctx, ch, time.Now())
			wantTables, wantDisks := 1, 1
			if boundary == "before first read" {
				wantTables, wantDisks = 0, 0
			} else if boundary == "after table read" {
				wantDisks = 0
			}
			if !errors.Is(err, context.Canceled) || ch.tables != wantTables || ch.disks != wantDisks {
				t.Fatalf("cancellation did not stop observation: %+v, %v", ch, err)
			}
			if boundary == "after rejected disk" && !strings.Contains(err.Error(), "Capacity:10000 Free:500 Unreserved:600 KeepFree:1000") {
				t.Fatalf("lost rejected tuple on cancellation: %v", err)
			}
		})
	}
}

// Uses only disposable PostgreSQL via the existing explicit opt-in. All CH
// observations and ALTER calls use the in-process fake; no real CH table is read
// or reset. Root runs this exact test after verifying fixture ownership.
func TestEmergencyObservationControllerIsolated(t *testing.T) {
	for _, preDispatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("pre-dispatch=%t", preDispatch), func(t *testing.T) {
			s, ctx := emergencyTestStore(t)
			ch := &emergencyObservationCH{base: fakeEmergency()}
			ch.edit = func(kind string, count int, rows []map[string]any) error {
				if kind == "disk" && (!preDispatch || count > 1) {
					rows[0]["unreserved_space"] = 500 + count
				}
				return nil
			}
			err := s.emergencyStep(ctx, ch, time.Now())
			wantReads := 3
			if preDispatch {
				wantReads++
			}
			if err == nil || ch.tables != wantReads || ch.disks != wantReads || ch.base.calls != 0 {
				t.Fatalf("rejected capacity dispatched or was not fully resampled: %+v, %v", ch, err)
			}
			v := testView(t, s, ctx)
			if v.Status.State != "unavailable" || v.Status.UsedPercent != nil || v.Status.Pending != nil || len(v.RecentActions) != 0 {
				t.Fatalf("rejected capacity authorized a usable state: %+v", v)
			}
			var actions, audits int
			if err := s.PG.QueryRow(ctx, "SELECT count(*) FROM storage_emergency_actions").Scan(&actions); err != nil {
				t.Fatal(err)
			}
			if err := s.PG.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action IN ('storage.emergency.prepared','storage.emergency.executing')").Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if actions != 0 || audits != 0 {
				t.Fatalf("rejected capacity created deletion authority: actions=%d audits=%d", actions, audits)
			}
			// A later coherent recovery can restore normal status, without
			// interpreting an earlier rejected sample as permission to delete.
			ch.edit = nil
			ch.base.used = []int{80}
			if err := s.emergencyStep(ctx, ch, time.Now()); err != nil {
				t.Fatal(err)
			}
			v = testView(t, s, ctx)
			if v.Status.State != "normal" || v.Status.Active || v.Status.UsedPercent == nil || *v.Status.UsedPercent != 80 || len(v.RecentActions) != 0 || ch.base.calls != 0 {
				t.Fatalf("coherent recovery not usable: %+v", v)
			}
		})
	}
}
