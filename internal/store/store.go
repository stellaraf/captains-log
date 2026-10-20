package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stellaraf/captains-log/internal/panos"
	"log/slog"
)

type Store struct {
	StorageMaintenancePath string
	CH                     *ClickHouse
	PG                     *pgxpool.Pool
}

var Columns = map[string]string{
	"raw_base64": "string", "id": "string", "ingested_at": "time", "received_at": "time", "generated_at": "time", "sender_ip": "string", "serial": "string", "device_name": "string", "vsys": "string", "log_type": "string", "wire_type": "string", "subtype": "string", "schema_version": "string", "schema_id": "string", "panos_version": "string", "timestamp_timezone": "string", "parser_version": "string", "parse_status": "string", "parse_error": "string", "raw": "string", "fields": "string", "extra_fields": "string", "src_ip": "string", "dst_ip": "string", "src_port": "number", "dst_port": "number", "src_zone": "string", "dst_zone": "string", "src_user": "string", "dst_user": "string", "app": "string", "previous_app": "string", "action": "string", "rule": "string", "session_end_reason": "string", "bytes": "number", "bytes_sent": "number", "bytes_received": "number", "packets": "number", "session_id": "string", "nat_src_ip": "string", "nat_dst_ip": "string", "severity": "string", "description": "string",
}

func (s *Store) Insert(ctx context.Context, events []panos.Event) error {
	rows := make([]map[string]any, 0, len(events))
	devices := map[string]map[string]any{}
	for _, event := range events {
		b, e := json.Marshal(event)
		if e != nil {
			return e
		}
		var original map[string]any
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber()
		d := decoder.Decode(&original)
		if d != nil {
			return d
		}
		row := map[string]any{}
		for name, kind := range Columns {
			v, ok := original[name]
			if name == "fields" || name == "extra_fields" {
				j, _ := json.Marshal(v)
				row[name] = string(j)
				continue
			}
			if !ok || v == nil {
				if kind == "number" {
					v = 0
				} else if kind == "time" {
					v = nil
				} else {
					v = ""
				}
			}
			if kind == "string" {
				v = fmt.Sprint(v)
			}
			row[name] = v
		}
		if row["received_at"] == nil {
			row["received_at"] = row["ingested_at"]
		}
		// Retained for schema compatibility only. Normal expiry is current policy
		// over immutable ingested_at; no arrival-time TTL may override an extension.
		row["expires_at"] = "2100-01-01T00:00:00Z"
		rows = append(rows, row)
		if serial := fmt.Sprint(row["serial"]); serial != "" {
			devices[serial] = row
		}
	}
	if e := s.insertEmergencyGuarded(ctx, rows); e != nil {
		return e
	}
	// Log data is already durable. Metadata failure must not turn an acknowledged
	// ClickHouse batch into an unnecessary replay; discovery also reconciles on read.
	for serial, row := range devices {
		_, e := s.PG.Exec(ctx, `INSERT INTO firewalls(serial,device_name,sender_ip,panos_version,first_seen,last_seen) VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT(serial) DO UPDATE SET device_name=EXCLUDED.device_name,sender_ip=EXCLUDED.sender_ip,last_seen=GREATEST(firewalls.last_seen,EXCLUDED.last_seen),panos_version=CASE WHEN EXCLUDED.panos_version='' THEN firewalls.panos_version ELSE EXCLUDED.panos_version END`, serial, row["device_name"], row["sender_ip"], row["panos_version"], row["ingested_at"])
		if e != nil {
			slog.Error("firewall discovery metadata write failed; will reconcile", "error", e)
		}
	}
	return nil
}
