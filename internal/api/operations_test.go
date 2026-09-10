package api

import (
	"context"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stellaraf/captains-log/internal/store"
)

func rateWindow(t *testing.T, rates map[string]any, kind, name string) map[string]any {
	t.Helper()
	return rates[kind].(map[string]any)[name].(map[string]any)
}

func TestFirewallRatesDistinguishShortHistoryAndObservedZero(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 6, 30, 0, time.UTC)
	short := map[string]any{"first_seen": now.Add(-30 * time.Second).Format(time.RFC3339), "events_60s": 120}
	rates := firewallRates(short, now, 90)
	if rateWindow(t, rates, "averages", "60s")["eps"] != nil || rateWindow(t, rates, "peaks", "1m")["eps"] != nil {
		t.Fatal("partial history became a whole-window rate", rates)
	}
	old := map[string]any{"first_seen": now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)}
	rates = firewallRates(old, now, 90)
	if rateWindow(t, rates, "averages", "7d")["eps"] != float64(0) || rateWindow(t, rates, "averages", "7d")["history_covers_window"] != true {
		t.Fatal("known retained-history zero lost", rates)
	}
	if rates["observation_continuity"] != "not_verified" {
		t.Fatal("outage-free observation incorrectly inferred")
	}
	rates = firewallRates(old, now, 1)
	if rateWindow(t, rates, "averages", "7d")["eps"] != nil || rateWindow(t, rates, "peaks", "1m")["history_covers_window"] != false {
		t.Fatal("short retention accepted as full lookback", rates)
	}
}

func TestStorageForecastUsesWrittenDemandReserveAndUnknownZero(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	row := map[string]any{"first_observed": now.Add(-8 * 24 * time.Hour).Format(time.RFC3339), "observations": 10, "bytes_7d": 238e9, "events_7d": 160272000}
	measurement := storageWriteMeasurements(row, now)
	forecast := storageForecast(1e12, 400e9, 500e9, measurement)
	if forecast["daily_growth_bytes"] != 34e9 || forecast["forecast_window"] != "7d" {
		t.Fatal(forecast)
	}
	if math.Abs(number(forecast["estimated_retention_days"])-750e9/34e9) > 1e-9 || math.Abs(number(forecast["days_until_reserve"])-250e9/34e9) > 1e-9 {
		t.Fatal("non-log usage or reserve omitted", forecast)
	}
	if rateWindow(t, measurement, "windows", "7d")["average_eps"] != float64(265) {
		t.Fatal(measurement)
	}
	row["bytes_7d"] = 0
	if storageForecast(1e12, 400e9, 500e9, storageWriteMeasurements(row, now))["estimated_retention_days"] != nil {
		t.Fatal("zero growth became infinite/zero retention")
	}
	row["first_observed"] = now.Add(-time.Hour).Format(time.RFC3339)
	row["bytes_24h"] = 34e9
	if storageForecast(1e12, 400e9, 500e9, storageWriteMeasurements(row, now))["daily_growth_bytes"] != nil {
		t.Fatal("partial day extrapolated as measured day")
	}
}

func TestStorageRecommendationExactBoundaryDoesNotAddExtra100GB(t *testing.T) {
	measurement := map[string]any{"windows": map[string]any{"24h": map[string]any{"history_covers_window": true, "daily_written_bytes": 85e9 / 30}}}
	forecast := storageForecast(1e12, 1e12, 0, measurement)
	first := forecast["requirements"].([]map[string]any)[0]
	if first["recommended_bytes"] != 100e9 {
		t.Fatal(first)
	}
}

func operationClickHouse(t *testing.T) *store.ClickHouse {
	t.Helper()
	endpoint := os.Getenv("NEBULALOG_TEST_CH_URL")
	if endpoint == "" {
		t.Skip("set NEBULALOG_TEST_CH_URL for read-only inline ClickHouse calculations")
	}
	return store.NewClickHouse(endpoint, os.Getenv("NEBULALOG_TEST_CH_USER"), os.Getenv("NEBULALOG_TEST_CH_PASSWORD"))
}

func TestInventoryWindowCalculationsClickHouse(t *testing.T) {
	client := operationClickHouse(t)
	// Inline table functions only: no INSERT, CREATE, mutation, or real log read.
	const source = `(
	SELECT 'A' AS serial,'old' AS device_name,'192.0.2.1' AS sender_ip,toDateTime64('2026-09-01 12:06:29',6,'UTC') AS ingested_at FROM numbers(1)
	UNION ALL SELECT 'A','alpha','192.0.2.2',toDateTime64('2026-09-08 11:00:10',6,'UTC') FROM numbers(3600)
	UNION ALL SELECT 'A','alpha','192.0.2.2',toDateTime64('2026-09-08 12:00:10',6,'UTC') FROM numbers(120)
	UNION ALL SELECT 'A','alpha','192.0.2.2',toDateTime64('2026-09-08 12:04:10',6,'UTC') FROM numbers(60)
	UNION ALL SELECT 'A','latest','192.0.2.3',toDateTime64('2026-09-08 12:06:10',6,'UTC') FROM numbers(600)
	UNION ALL SELECT 'A','future','192.0.2.4',toDateTime64('2026-09-08 12:06:30',6,'UTC') FROM numbers(1000)
	UNION ALL SELECT 'B','new','192.0.2.5',toDateTime64('2026-09-08 12:06:10',6,'UTC') FROM numbers(600)
	UNION ALL SELECT 'C','partial','192.0.2.6',toDateTime64('2026-09-08 12:04:00.500',6,'UTC') FROM numbers(1000)
	UNION ALL SELECT 'C','partial','192.0.2.6',toDateTime64('2026-09-08 12:05:10',6,'UTC') FROM numbers(60)
	)`
	asOf := time.Date(2026, 9, 8, 12, 6, 30, 0, time.UTC)
	params := map[string]string{"as_of": asOf.Format(time.RFC3339), "serial_filter": ""}
	rows, err := client.Rows(context.Background(), firewallRateSQL(source), params)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatal(rows)
	}
	row := rows[0]
	for key, want := range map[string]float64{"events_60s": 600, "events_1h": 780, "events_24h": 4380, "events_7d": 4380, "peak_1m_events": 3600, "peak_5m_events": 3600, "peak_1h_events": 3600} {
		if number(row[key]) != want {
			t.Fatalf("%s got %v want %v", key, row[key], want)
		}
	}
	if row["device_name"] != "latest" || row["sender_ip"] != "192.0.2.3" {
		t.Fatal("latest metadata was not timestamp selected", row)
	}
	rates := firewallRates(row, asOf, 90)
	for _, want := range []struct {
		kind, name string
		value      float64
	}{{"averages", "60s", 10}, {"averages", "1h", 780.0 / 3600}, {"peaks", "1m", 60}, {"peaks", "5m", 12}, {"peaks", "1h", 1}} {
		if number(rateWindow(t, rates, want.kind, want.name)["eps"]) != want.value {
			t.Fatal(want, rates)
		}
	}
	if rateWindow(t, firewallRates(rows[1], asOf, 90), "averages", "60s")["eps"] != nil {
		t.Fatal("new device history fabricated")
	}
	if number(rows[2]["peak_1m_events"]) != 60 {
		t.Fatal("partial initial bucket included in peak", rows[2])
	}
	params["serial_filter"] = "A"
	rows, err = client.Rows(context.Background(), firewallRateSQL(source), params)
	if err != nil || len(rows) != 1 || rows[0]["serial"] != "A" {
		t.Fatal(err, rows)
	}
	params["serial_filter"] = "A' OR 1=1 --"
	rows, err = client.Rows(context.Background(), firewallRateSQL(source), params)
	if err != nil || len(rows) != 0 {
		t.Fatal("serial scope bypass", err, rows)
	}
	if strings.Contains(firewallRateSQL(source), "generated_at") || strings.Contains(firewallRateSQL(source), "received_at") {
		t.Fatal("firewall clocks used for appliance EPS")
	}
}

func TestStorageWriteDemandClickHouse(t *testing.T) {
	client := operationClickHouse(t)
	const source = `values('database String, table String, event_time DateTime, event_type String, error UInt16, rows UInt64, size_in_bytes UInt64',
	('nebulalog','events','2026-09-01 11:59:59','NewPart',0,1,100),
	('nebulalog','events','2026-09-08 11:00:00','NewPart',0,1000,34000000000),
	('nebulalog','events','2026-09-08 11:00:01','MergeParts',0,1000,999999999999),
	('nebulalog','events','2026-09-08 11:00:02','MutatePart',0,1000,999999999999),
	('nebulalog','events','2026-09-08 11:00:03','NewPart',1,1000,999999999999),
	('nebulalog','unrelated','2026-09-08 11:00:04','NewPart',0,1000,999999999999),
	('nebulalog','events','2026-09-08 12:00:00','NewPart',0,1000,999999999999))`
	rows, err := client.Rows(context.Background(), storageWriteSQL(source), map[string]string{"as_of": "2026-09-08T12:00:00Z"})
	if err != nil || len(rows) != 1 {
		t.Fatal(err, rows)
	}
	for _, window := range []string{"1h", "24h", "7d"} {
		if number(rows[0]["bytes_"+window]) != 34e9 || number(rows[0]["events_"+window]) != 1000 {
			t.Fatal("merge, mutation, failed insert or unrelated bytes counted", rows)
		}
	}
}
