package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type EmergencyIdentity struct {
	TableUUID     string `json:"table_uuid"`
	Engine        string `json:"engine"`
	PartitionKey  string `json:"partition_key"`
	StoragePolicy string `json:"storage_policy"`
	DataPath      string `json:"data_path"`
	DiskName      string `json:"disk_name"`
	DiskPath      string `json:"disk_path"`
}
type EmergencyMeasurement struct {
	Identity    EmergencyIdentity `json:"identity"`
	ObservedAt  time.Time         `json:"observed_at"`
	Capacity    uint64            `json:"capacity_bytes"`
	Free        uint64            `json:"free_bytes"`
	Unreserved  uint64            `json:"unreserved_bytes"`
	KeepFree    uint64            `json:"keep_free_bytes"`
	Available   uint64            `json:"available_bytes"`
	UsedPercent float64           `json:"used_percent"`
}
type EmergencyPartition struct {
	PartitionID  string          `json:"partition_id"`
	LogType      string          `json:"log_type"`
	PartitionDay string          `json:"partition_day"`
	Parts        []EmergencyPart `json:"parts"`
	Rows         uint64          `json:"rows"`
	Bytes        uint64          `json:"bytes_on_disk"`
}
type EmergencyPart struct {
	Name  string `json:"name"`
	Rows  uint64 `json:"rows"`
	Bytes uint64 `json:"bytes_on_disk"`
}
type EmergencyPlan struct {
	EmergencyPartition
	PolicyRevision int64                `json:"policy_revision"`
	Policy         EmergencyPolicy      `json:"policy"`
	TableUUID      string               `json:"table_uuid"`
	Before         EmergencyMeasurement `json:"before"`
	QueryID        string               `json:"query_id"`
}
type EmergencyAction struct {
	EmergencyPlan
	ID        string    `json:"id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Message   string    `json:"message"`
}
type emergencyClickHouse interface {
	Rows(context.Context, string, map[string]string) ([]map[string]any, error)
	ExecWithQueryID(context.Context, string, map[string]string, string) error
}

var emergencyUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var emergencyPartitionValue = regexp.MustCompile(`^\('([a-z]+)', ?'([0-9]{4}-[0-9]{2}-[0-9]{2})'\)$`)
var emergencyPartitionID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func emergencyUint(row map[string]any, key string) (uint64, error) {
	v, ok := row[key]
	if !ok {
		return 0, fmt.Errorf("missing storage observation: %s", key)
	}
	x, err := strconv.ParseUint(fmt.Sprint(v), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid storage observation: %s", key)
	}
	return x, nil
}
func emergencyString(row map[string]any, key string) (string, error) {
	v, ok := row[key].(string)
	if !ok || v == "" || len(v) > 4096 {
		return "", fmt.Errorf("invalid storage identity: %s", key)
	}
	return v, nil
}

func observeEmergency(ctx context.Context, ch emergencyClickHouse, now time.Time) (EmergencyMeasurement, error) {
	// ClickHouse reads free_space and unreserved_space separately. A concurrent
	// cleanup can increase the latter between those reads. Resample the whole
	// identity and capacity observation, never clamp or use the rejected tuple.
	type capacitySample struct {
		Capacity, Free, Unreserved, KeepFree uint64
	}
	var rejected []capacitySample
	fail := func(m EmergencyMeasurement, err error) (EmergencyMeasurement, error) {
		if len(rejected) > 0 {
			err = fmt.Errorf("%w; rejected capacity observations: %+v", err, rejected)
		}
		return m, err
	}
	var identity EmergencyIdentity
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return fail(EmergencyMeasurement{ObservedAt: now.UTC()}, err)
		}
		m, err := readEmergencyMeasurement(ctx, ch, now)
		if err != nil {
			return fail(m, err)
		}
		inconsistent := m.Capacity == 0 || m.Free > m.Capacity || m.Unreserved > m.Free
		if inconsistent {
			rejected = append(rejected, capacitySample{m.Capacity, m.Free, m.Unreserved, m.KeepFree})
		}
		if err := ctx.Err(); err != nil {
			return fail(m, err)
		}
		if attempt > 0 && m.Identity != identity {
			return fail(m, errors.New("storage identity changed during capacity resampling"))
		}
		identity = m.Identity
		if inconsistent {
			if m.Capacity > 0 && m.Free <= m.Capacity && m.Unreserved <= m.Capacity && attempt < 2 {
				continue
			}
			return fail(m, errors.New("inconsistent disk capacity observation"))
		}
		m.Available = m.Unreserved // ClickHouse already subtracts keep_free_space from total/free/unreserved.
		m.UsedPercent = 100 * (1 - float64(m.Available)/float64(m.Capacity))
		return m, nil
	}
	panic("unreachable capacity resampling state")
}

// Each attempt validates every identity and scalar before capacity consistency
// is evaluated. Read, schema and identity errors are never retried.
func readEmergencyMeasurement(ctx context.Context, ch emergencyClickHouse, now time.Time) (EmergencyMeasurement, error) {
	m := EmergencyMeasurement{ObservedAt: now.UTC()}
	tables, err := ch.Rows(ctx, `SELECT toString(uuid) AS uuid,engine,partition_key,storage_policy,data_paths,(SELECT engine FROM system.databases WHERE name='nebulalog') AS database_engine FROM system.tables WHERE database='nebulalog' AND name='events'`, nil)
	if err != nil {
		return m, err
	}
	if len(tables) != 1 {
		return m, errors.New("one supported events table is required")
	}
	r := tables[0]
	id := EmergencyIdentity{}
	for key, target := range map[string]*string{"uuid": &id.TableUUID, "engine": &id.Engine, "partition_key": &id.PartitionKey, "storage_policy": &id.StoragePolicy} {
		if *target, err = emergencyString(r, key); err != nil {
			return m, err
		}
	}
	if r["database_engine"] != "Atomic" || !emergencyUUID.MatchString(id.TableUUID) || id.TableUUID == "00000000-0000-0000-0000-000000000000" || id.Engine != "MergeTree" || id.PartitionKey != "(log_type, toDate(ingested_at))" || id.StoragePolicy != "default" {
		return m, errors.New("unsupported table engine, partition scheme or storage policy")
	}
	paths, ok := r["data_paths"].([]any)
	if !ok || len(paths) != 1 {
		return m, errors.New("exactly one table data path is required")
	}
	id.DataPath, ok = paths[0].(string)
	if !ok {
		return m, errors.New("invalid table data path")
	}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	disks, err := ch.Rows(ctx, `SELECT name,path,type,total_space,free_space,unreserved_space,keep_free_space,is_read_only,is_remote FROM system.disks WHERE name='default'`, nil)
	if err != nil {
		return m, err
	}
	if len(disks) != 1 {
		return m, errors.New("one local default disk is required")
	}
	r = disks[0]
	if id.DiskName, err = emergencyString(r, "name"); err != nil {
		return m, err
	}
	if id.DiskPath, err = emergencyString(r, "path"); err != nil {
		return m, err
	}
	ro, err := emergencyUint(r, "is_read_only")
	if err != nil {
		return m, err
	}
	remote, err := emergencyUint(r, "is_remote")
	if err != nil {
		return m, err
	}
	if r["type"] != "Local" || ro != 0 || remote != 0 || id.DiskName != "default" || id.DiskPath != "/var/lib/clickhouse/" || !strings.HasPrefix(id.DataPath, id.DiskPath+"store/") || path.Clean(id.DataPath)+"/" != id.DataPath || !strings.Contains(id.DataPath, "/"+id.TableUUID+"/") {
		return m, errors.New("unsupported or unsafe disk identity")
	}
	for key, target := range map[string]*uint64{"total_space": &m.Capacity, "free_space": &m.Free, "unreserved_space": &m.Unreserved, "keep_free_space": &m.KeepFree} {
		if *target, err = emergencyUint(r, key); err != nil {
			return m, err
		}
	}
	m.Identity = id
	return m, nil
}

// Only complete category/day partitions strictly outside the configured age
// can be candidates. A virtual UI view or unknown partition is never a fallback.
func eligibleEmergencyPartitions(rows []map[string]any, p EmergencyPolicy, now time.Time) ([]EmergencyPartition, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	out := []EmergencyPartition{}
	seen := map[string]bool{}
	for _, row := range rows {
		id, err := emergencyString(row, "partition_id")
		if err != nil {
			return nil, err
		}
		if !emergencyPartitionID.MatchString(id) || seen[id] {
			return nil, errors.New("invalid or duplicated partition identity")
		}
		seen[id] = true
		value, err := emergencyString(row, "partition")
		if err != nil {
			return nil, err
		}
		match := emergencyPartitionValue.FindStringSubmatch(value)
		if match == nil {
			continue
		}
		days, known := p.MinimumDays[match[1]]
		if !known {
			continue
		}
		day, err := time.Parse("2006-01-02", match[2])
		if err != nil {
			continue
		}
		if !day.AddDate(0, 0, 1).Before(now.UTC().AddDate(0, 0, -days)) {
			continue
		}
		count, err := emergencyUint(row, "rows")
		if err != nil {
			return nil, err
		}
		bytes, err := emergencyUint(row, "bytes_on_disk")
		if err != nil {
			return nil, err
		}
		if row["disk_name"] != "default" || count == 0 || bytes == 0 {
			return nil, errors.New("unmeasured or unsupported partition")
		}
		parts, ok := row["parts"].([]EmergencyPart)
		if !ok || len(parts) == 0 {
			return nil, errors.New("exact partition parts unavailable")
		}
		out = append(out, EmergencyPartition{PartitionID: id, LogType: match[1], PartitionDay: match[2], Rows: count, Bytes: bytes, Parts: parts})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].LogType == "traffic") != (out[j].LogType == "traffic") {
			return out[i].LogType == "traffic"
		}
		if out[i].PartitionDay != out[j].PartitionDay {
			return out[i].PartitionDay < out[j].PartitionDay
		}
		return out[i].PartitionID < out[j].PartitionID
	})
	return out, nil
}

const emergencyPartsSQL = `SELECT partition_id,partition,name,disk_name,rows,bytes_on_disk FROM system.parts WHERE database='nebulalog' AND table='events' AND active ORDER BY partition_id,name LIMIT 65537`

func inspectEmergencyPartitions(ctx context.Context, ch emergencyClickHouse, p EmergencyPolicy, now time.Time) ([]EmergencyPartition, error) {
	combined, err := inspectPartitionGroups(ctx, ch)
	if err != nil {
		return nil, err
	}
	return eligibleEmergencyPartitions(combined, p, now)
}

func inspectPartitionGroups(ctx context.Context, ch emergencyClickHouse) ([]map[string]any, error) {
	rows, err := ch.Rows(ctx, emergencyPartsSQL, nil)
	if err != nil {
		return nil, err
	}
	if len(rows) > 65536 {
		return nil, errors.New("part inventory exceeds bounded limit")
	}
	grouped := map[string]map[string]any{}
	names := map[string]bool{}
	for _, r := range rows {
		id, e := emergencyString(r, "partition_id")
		if e != nil {
			return nil, e
		}
		value, e := emergencyString(r, "partition")
		if e != nil {
			return nil, e
		}
		name, e := emergencyString(r, "name")
		if e != nil {
			return nil, e
		}
		if names[name] || r["disk_name"] != "default" {
			return nil, errors.New("duplicate or unqualified part")
		}
		names[name] = true
		n, e := emergencyUint(r, "rows")
		if e != nil {
			return nil, e
		}
		size, e := emergencyUint(r, "bytes_on_disk")
		if e != nil {
			return nil, e
		}
		g := grouped[id]
		if g == nil {
			g = map[string]any{"partition_id": id, "partition": value, "disk_name": "default", "rows": uint64(0), "bytes_on_disk": uint64(0), "parts": []EmergencyPart{}}
			grouped[id] = g
		}
		if g["partition"] != value {
			return nil, errors.New("partition identity mismatch")
		}
		oldRows, oldBytes := g["rows"].(uint64), g["bytes_on_disk"].(uint64)
		if oldRows+n < oldRows || oldBytes+size < oldBytes {
			return nil, errors.New("partition size overflow")
		}
		g["rows"], g["bytes_on_disk"] = oldRows+n, oldBytes+size
		g["parts"] = append(g["parts"].([]EmergencyPart), EmergencyPart{name, n, size})
	}
	combined := make([]map[string]any, 0, len(grouped))
	for _, g := range grouped {
		combined = append(combined, g)
	}
	return combined, nil
}

func verifyEmergencyRows(ctx context.Context, ch emergencyClickHouse, c EmergencyPartition) (bool, error) {
	rows, err := ch.Rows(ctx, `SELECT count() AS rows,countIf(parse_status!='parsed') AS diagnostics,min(log_type) AS first_type,max(log_type) AS last_type,toString(min(toDate(ingested_at))) AS first_day,toString(max(toDate(ingested_at))) AS last_day FROM nebulalog.events WHERE _partition_id={partition:String}`, map[string]string{"partition": c.PartitionID})
	if err != nil {
		return false, err
	}
	if len(rows) != 1 {
		return false, errors.New("partition row proof unavailable")
	}
	r := rows[0]
	n, err := emergencyUint(r, "rows")
	if err != nil {
		return false, err
	}
	diagnostics, err := emergencyUint(r, "diagnostics")
	if err != nil {
		return false, err
	}
	return diagnostics == 0 && n == c.Rows && r["first_type"] == c.LogType && r["last_type"] == c.LogType && r["first_day"] == c.PartitionDay && r["last_day"] == c.PartitionDay, nil
}

func sameEmergencyPlan(a, b EmergencyPartition) bool {
	return string(emergencyJSON(a)) == string(emergencyJSON(b))
}
func emergencyJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
