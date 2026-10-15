package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"
)

func number(v any) float64 { f, _ := strconv.ParseFloat(fmt.Sprint(v), 64); return f }

// source is a fixed program fragment (events in production, inline VALUES in
// integration tests). Every request value remains a bound ClickHouse parameter.
func firewallRateSQL(source string) string {
	return `WITH parseDateTime64BestEffort({as_of:String},6,'UTC') AS cutoff,
	grouped AS (
	 SELECT serial,width,if(width=0,0,intDiv(toUnixTimestamp(ingested_at),greatest(width,1))*width) AS bucket,
	 min(ingested_at) AS first_event,max(ingested_at) AS last_event,
	 argMax(device_name,ingested_at) AS device_name,argMax(sender_ip,ingested_at) AS sender_ip,
	 count() AS n,countIf(ingested_at>=cutoff-INTERVAL 60 SECOND) AS n60,
	 countIf(ingested_at>=cutoff-INTERVAL 1 HOUR) AS n1h,countIf(ingested_at>=cutoff-INTERVAL 1 DAY) AS n24h,
	 countIf(ingested_at>=cutoff-INTERVAL 7 DAY) AS n7d,countIf(ingested_at>=toStartOfDay(cutoff,'UTC')) AS today
	 FROM ` + source + ` ARRAY JOIN [toUInt32(0),60,300,3600] AS width
	 WHERE ingested_at>=cutoff-INTERVAL 8 DAY AND ingested_at<cutoff AND serial!=''
	 AND ({serial_filter:String}='' OR serial={serial_filter:String}) GROUP BY serial,width,bucket
	), observed AS (SELECT *,min(first_event) OVER (PARTITION BY serial) AS observed_since FROM grouped)
	SELECT serial,minIf(first_event,width=0) AS first_seen,maxIf(last_event,width=0) AS last_seen,
	 argMaxIf(device_name,last_event,width=0) AS device_name,argMaxIf(sender_ip,last_event,width=0) AS sender_ip,
	 maxIf(n60,width=0) AS events_60s,maxIf(n1h,width=0) AS events_1h,maxIf(n24h,width=0) AS events_24h,
	 maxIf(n7d,width=0) AS events_7d,maxIf(today,width=0) AS events_today,
	 maxIf(n,width=60 AND bucket>=toUnixTimestamp(cutoff)-604800 AND toDateTime64(bucket,6,'UTC')>=observed_since AND bucket+60<=toUnixTimestamp(cutoff)) AS peak_1m_events,
	 maxIf(n,width=300 AND bucket>=toUnixTimestamp(cutoff)-604800 AND toDateTime64(bucket,6,'UTC')>=observed_since AND bucket+300<=toUnixTimestamp(cutoff)) AS peak_5m_events,
	 maxIf(n,width=3600 AND bucket>=toUnixTimestamp(cutoff)-604800 AND toDateTime64(bucket,6,'UTC')>=observed_since AND bucket+3600<=toUnixTimestamp(cutoff)) AS peak_1h_events
	 FROM observed GROUP BY serial ORDER BY serial
	 SETTINGS max_rows_to_group_by=2000000,group_by_overflow_mode='throw',max_result_rows=10000,result_overflow_mode='throw'`
}

func observationTime(value any) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(value))
	return parsed
}

func firewallRates(row map[string]any, asOf time.Time, retentionDays int) map[string]any {
	since := observationTime(row["first_seen"])
	result := map[string]any{"as_of": asOf, "timestamp_source": "ingested_at", "source": "retained_events",
		"observation_continuity": "not_verified", "historical_retention_changes": "not_verified", "minimum_configured_retention_days": retentionDays,
		"observed_since": nil, "averages": map[string]any{}, "peaks": map[string]any{}}
	if !since.IsZero() {
		result["observed_since"] = since
	}
	averages := result["averages"].(map[string]any)
	for _, window := range []struct {
		name, key string
		seconds   int64
	}{{"60s", "events_60s", 60}, {"1h", "events_1h", 3600}, {"24h", "events_24h", 86400}, {"7d", "events_7d", 604800}} {
		start := asOf.Add(-time.Duration(window.seconds) * time.Second)
		retentionCovers := int64(retentionDays)*86400 >= window.seconds
		complete := !since.IsZero() && !since.After(start) && retentionCovers
		var eps any
		if complete {
			eps = number(row[window.key]) / float64(window.seconds)
		}
		averages[window.name] = map[string]any{"eps": eps, "retained_events": number(row[window.key]), "from": start, "to": asOf, "seconds": window.seconds, "history_covers_window": complete, "retention_covers_window": retentionCovers, "quality": map[bool]string{true: "retained_history", false: "insufficient_history"}[complete]}
	}
	peaks := result["peaks"].(map[string]any)
	for _, window := range []struct {
		name, key string
		seconds   int64
	}{{"1m", "peak_1m_events", 60}, {"5m", "peak_5m_events", 300}, {"1h", "peak_1h_events", 3600}} {
		start := asOf.Add(-7 * 24 * time.Hour)
		if since.After(start) {
			start = since
		}
		first := time.Unix((start.Unix()+window.seconds-1)/window.seconds*window.seconds, 0).UTC()
		if start.Nanosecond() > 0 && first.Equal(start.Truncate(time.Second)) {
			first = first.Add(time.Duration(window.seconds) * time.Second)
		}
		last := asOf.Truncate(time.Duration(window.seconds) * time.Second)
		var eps any
		if !since.IsZero() && first.Before(last) {
			eps = number(row[window.key]) / float64(window.seconds)
		}
		complete := !since.IsZero() && !since.After(asOf.Add(-7*24*time.Hour)) && retentionDays >= 7
		quality := "insufficient_history"
		if eps != nil {
			quality = "partial_lookback"
			if complete {
				quality = "retained_history"
			}
		}
		peaks[window.name] = map[string]any{"eps": eps, "bucket_seconds": window.seconds, "lookback_seconds": 604800, "alignment": "UTC fixed buckets; completed only", "from": first, "to": last, "history_covers_window": complete, "retention_covers_window": retentionDays >= 7, "quality": quality}
	}
	return result
}

func (s *Server) firewalls(w http.ResponseWriter, r *http.Request) {
	serialFilter := r.PathValue("serial")
	if len(serialFilter) > 128 {
		problem(w, http.StatusBadRequest, "Invalid firewall serial")
		return
	}
	retention, e := s.Store.Retention(r.Context())
	if e != nil {
		databaseError(w, e)
		return
	}
	retentionDays := retention.GlobalDays
	for _, days := range retention.PerType {
		if days < retentionDays {
			retentionDays = days
		}
	}
	asOf := time.Now().UTC().Truncate(time.Second)
	rows, e := s.Store.CH.Rows(r.Context(), firewallRateSQL("events"), map[string]string{"serial_filter": serialFilter, "as_of": asOf.Format(time.RFC3339Nano)})
	if e != nil {
		databaseError(w, e)
		return
	}
	stats := map[string]map[string]any{}
	for _, row := range rows {
		serial := fmt.Sprint(row["serial"])
		stats[serial] = row
	}
	pg, e := s.Store.PG.Query(r.Context(), "SELECT row_to_json(f) FROM firewalls f WHERE $1='' OR serial=$1 ORDER BY friendly_name,serial LIMIT 10000", serialFilter)
	if e != nil {
		databaseError(w, e)
		return
	}
	defer pg.Close()
	metadata := map[string]map[string]any{}
	for pg.Next() {
		var b []byte
		if e = pg.Scan(&b); e != nil {
			databaseError(w, e)
			return
		}
		var f map[string]any
		_ = json.Unmarshal(b, &f)
		metadata[fmt.Sprint(f["serial"])] = f
	}
	if pg.Err() != nil {
		databaseError(w, pg.Err())
		return
	}
	for serial, row := range stats {
		if _, ok := metadata[serial]; !ok {
			metadata[serial] = map[string]any{"serial": serial, "friendly_name": "", "site": "", "tags": []string{}, "notes": "", "panos_version": "", "first_seen": row["first_seen"]}
		}
		storedFirst, retainedFirst := observationTime(metadata[serial]["first_seen"]), observationTime(row["first_seen"])
		if storedFirst.IsZero() || !retainedFirst.IsZero() && retainedFirst.Before(storedFirst) {
			metadata[serial]["first_seen"] = row["first_seen"]
		}
		for _, key := range []string{"last_seen", "device_name", "sender_ip"} {
			metadata[serial][key] = row[key]
		}
	}
	out := []map[string]any{}
	for serial, f := range metadata {
		row := stats[serial]
		rates := firewallRates(row, asOf, retentionDays)
		f["rate_windows"] = rates
		averages, peaks := rates["averages"].(map[string]any), rates["peaks"].(map[string]any)
		f["current_eps"] = averages["60s"].(map[string]any)["eps"]
		f["average_eps"] = averages["24h"].(map[string]any)["eps"]
		f["peak_eps"] = peaks["1m"].(map[string]any)["eps"]
		f["events_today"] = number(row["events_today"])
		f["status"] = "quiet"
		if number(row["events_60s"]) > 0 {
			f["status"] = "receiving"
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := fmt.Sprint(out[i]["friendly_name"]), fmt.Sprint(out[j]["friendly_name"])
		if left == right {
			return fmt.Sprint(out[i]["serial"]) < fmt.Sprint(out[j]["serial"])
		}
		return left < right
	})
	if serialFilter != "" {
		if len(out) == 0 {
			problem(w, http.StatusNotFound, "Firewall not found")
			return
		}
		respond(w, http.StatusOK, map[string]any{"firewall": out[0]})
		return
	}
	respond(w, 200, map[string]any{"firewalls": out})
}
func (s *Server) saveFirewall(w http.ResponseWriter, r *http.Request) {
	var v struct {
		FriendlyName string   `json:"friendly_name"`
		Site         string   `json:"site"`
		Tags         []string `json:"tags"`
		Notes        string   `json:"notes"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.FriendlyName) > 128 || len(v.Site) > 128 || len(v.Tags) > 32 || len(v.Notes) > 8192 {
		problem(w, 400, "Firewall metadata exceeds field limits")
		return
	}
	for _, tag := range v.Tags {
		if len(tag) > 64 {
			problem(w, 400, "Tags must be at most 64 characters")
			return
		}
	}
	tags, _ := json.Marshal(v.Tags)
	tx, e := s.Store.PG.Begin(r.Context())
	if e != nil {
		databaseError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	result, e := tx.Exec(r.Context(), "UPDATE firewalls SET friendly_name=$1,site=$2,tags=$3,notes=$4 WHERE serial=$5", v.FriendlyName, v.Site, tags, v.Notes, r.PathValue("serial"))
	if e != nil {
		databaseError(w, e)
		return
	}
	if result.RowsAffected() != 1 {
		problem(w, 404, "Firewall not found")
		return
	}
	if e = transactionAudit(r, tx, "firewall.update", r.PathValue("serial")); e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		databaseError(w, e)
		return
	}
	respond(w, 200, v)
}
func (s *Server) storage(w http.ResponseWriter, r *http.Request) {
	disks, e := s.Store.CH.Rows(r.Context(), "SELECT total_space,free_space FROM system.disks WHERE name='default'", nil)
	if e != nil {
		databaseError(w, e)
		return
	}
	parts, e := s.Store.CH.Rows(r.Context(), "SELECT coalesce(sum(bytes_on_disk),0) AS database_bytes,coalesce(sum(rows),0) AS events FROM system.parts WHERE active AND database='nebulalog' AND table='events'", nil)
	if e != nil || len(disks) == 0 || len(parts) == 0 {
		if e == nil {
			e = fmt.Errorf("no storage measurement available")
		}
		databaseError(w, e)
		return
	}
	capacity := number(disks[0]["total_space"])
	free := number(disks[0]["free_space"])
	db := number(parts[0]["database_bytes"])
	events := number(parts[0]["events"])
	// NewPart records measure inserted compressed parts without counting merge or
	// mutation rewrites. Their timestamps describe durable part creation, not the
	// firewall clock. Leave a full minute for asynchronous system-log flushing.
	asOf := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	writeRows, writeErr := s.Store.CH.Rows(r.Context(), storageWriteSQL("system.part_log"), map[string]string{"as_of": asOf.Format(time.RFC3339Nano)})
	measurement := map[string]any{"status": "unavailable", "source": "system.part_log successful NewPart records", "message": "Durable part-write observations are unavailable; retention demand is unknown."}
	if writeErr == nil && len(writeRows) == 1 {
		measurement = storageWriteMeasurements(writeRows[0], asOf)
	}
	forecast := storageForecast(capacity, free, db, measurement)
	status := "normal"
	used := capacity - free
	if capacity > 0 {
		pct := used / capacity
		switch {
		case pct >= .95:
			status = "emergency"
		case pct >= .90:
			status = "critical"
		case pct >= .80:
			status = "warning"
		case pct >= .70:
			status = "informational"
		}
	}
	var bpe any
	if events > 0 {
		bpe = db / events
	}
	forecast["capacity_bytes"], forecast["used_bytes"], forecast["available_bytes"] = capacity, used, free
	forecast["database_bytes"], forecast["events"], forecast["bytes_per_event"] = db, events, bpe
	forecast["status"], forecast["reserve_percent"] = status, 15
	forecast["write_measurements"] = measurement
	forecast["measurement"] = "ClickHouse default disk; demand uses successful initial NewPart bytes, excluding merges/mutations. Estimates require at least 24 hours of retained write history and remain conditional on observed log mix."
	var observed *applianceStatus
	if snapshot, err := s.hostStatus(); err == nil {
		observed = &snapshot
	}
	for key, value := range hostStorageResponse(observed, s.Config.ApplianceStatusPath != "") {
		forecast[key] = value
	}
	forecast["emergency_policy"] = "Emergency cleanup uses a separate versioned policy and verified controller observation at /api/storage/emergency. These capacity/forecast badges do not prove cleanup is operating; bounded spool pressure remains observable."
	respond(w, 200, forecast)
}

// source is fixed locally; the endpoint cannot select a table or SQL fragment.
func storageWriteSQL(source string) string {
	return `WITH parseDateTime64BestEffort({as_of:String},6,'UTC') AS cutoff
 SELECT min(event_time) AS first_observed,max(event_time) AS last_observed,count() AS observations,
 sumIf(size_in_bytes,event_type='NewPart' AND error=0 AND event_time>=cutoff-INTERVAL 1 HOUR) AS bytes_1h,
 sumIf(rows,event_type='NewPart' AND error=0 AND event_time>=cutoff-INTERVAL 1 HOUR) AS events_1h,
 sumIf(size_in_bytes,event_type='NewPart' AND error=0 AND event_time>=cutoff-INTERVAL 1 DAY) AS bytes_24h,
 sumIf(rows,event_type='NewPart' AND error=0 AND event_time>=cutoff-INTERVAL 1 DAY) AS events_24h,
 sumIf(size_in_bytes,event_type='NewPart' AND error=0 AND event_time>=cutoff-INTERVAL 7 DAY) AS bytes_7d,
 sumIf(rows,event_type='NewPart' AND error=0 AND event_time>=cutoff-INTERVAL 7 DAY) AS events_7d
 FROM ` + source + ` WHERE database='nebulalog' AND table='events' AND event_time>=cutoff-INTERVAL 8 DAY AND event_time<cutoff`
}

func storageWriteMeasurements(row map[string]any, asOf time.Time) map[string]any {
	since := observationTime(row["first_observed"])
	if number(row["observations"]) == 0 {
		since = time.Time{}
	}
	result := map[string]any{"status": "observed", "source": "system.part_log successful NewPart records", "timestamp_source": "part creation event_time", "as_of": asOf, "observed_since": nil, "observation_continuity": "not_verified", "windows": map[string]any{}, "bytes_basis": "Initial compressed part bytes including part overhead; merge/mutation/download rewrites excluded. Final merged size can differ."}
	if !since.IsZero() {
		result["observed_since"] = since
	}
	windows := result["windows"].(map[string]any)
	for _, window := range []struct {
		name    string
		seconds int64
	}{{"1h", 3600}, {"24h", 86400}, {"7d", 604800}} {
		complete := !since.IsZero() && !since.After(asOf.Add(-time.Duration(window.seconds)*time.Second))
		written, events := number(row["bytes_"+window.name]), number(row["events_"+window.name])
		var daily, eps, bpe any
		if complete {
			daily = written * 86400 / float64(window.seconds)
			eps = events / float64(window.seconds)
			if events > 0 {
				bpe = written / events
			}
		}
		windows[window.name] = map[string]any{"seconds": window.seconds, "from": asOf.Add(-time.Duration(window.seconds) * time.Second), "to": asOf, "written_bytes": written, "events": events, "daily_written_bytes": daily, "average_eps": eps, "bytes_per_event": bpe, "history_covers_window": complete, "quality": map[bool]string{true: "retained_history", false: "insufficient_history"}[complete]}
	}
	return result
}

func storageForecast(capacity, free, databaseBytes float64, measurement map[string]any) map[string]any {
	result := map[string]any{"daily_growth_bytes": nil, "estimated_retention_days": nil, "days_until_full": nil, "days_until_reserve": nil, "requirements": []map[string]any{}, "forecast_status": "insufficient_history", "forecast_window": nil}
	windows, ok := measurement["windows"].(map[string]any)
	if !ok {
		result["forecast_status"] = "unavailable"
		return result
	}
	for _, name := range []string{"7d", "24h"} {
		window, ok := windows[name].(map[string]any)
		if !ok || window["history_covers_window"] != true {
			continue
		}
		rate := number(window["daily_written_bytes"])
		if rate <= 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
			continue
		}
		nonLogUsed := math.Max(0, capacity-free-databaseBytes)
		result["daily_growth_bytes"], result["forecast_window"], result["forecast_status"] = rate, name, "preliminary"
		result["estimated_retention_days"] = math.Max(0, capacity*.85-nonLogUsed) / rate
		result["days_until_full"] = math.Max(0, free) / rate
		result["days_until_reserve"] = math.Max(0, capacity*.85-(capacity-free)) / rate
		requirements := []map[string]any{}
		for _, days := range []int{30, 60, 90, 180, 365} {
			need := (rate*float64(days) + nonLogUsed) / .85
			requirements = append(requirements, map[string]any{"days": days, "required_bytes": need, "recommended_bytes": math.Ceil(need/1e11) * 1e11})
		}
		result["requirements"] = requirements
		break
	}
	return result
}
