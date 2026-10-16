package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// The host owns this gate under EmergencyLockID. Operation is SHA-256 of the
// canonical protected host stage path; no TTL or application endpoint clears it.
type emergencyMaintenance struct {
	Schema       int     `json:"schema"`
	Held         bool    `json:"held"`
	DeliveryHeld bool    `json:"delivery_held"`
	Operation    *string `json:"operation"`
}

var emergencyOperation = regexp.MustCompile(`^[a-f0-9]{64}$`)

func readEmergencyMaintenance(ctx context.Context, q emergencyQuerier) (emergencyMaintenance, error) {
	var gate emergencyMaintenance
	var raw []byte
	if err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key='storage_emergency_maintenance'").Scan(&raw); err != nil {
		return gate, err
	}
	return parseEmergencyMaintenance(raw)
}
func parseEmergencyMaintenance(raw []byte) (emergencyMaintenance, error) {
	var gate emergencyMaintenance
	if len(raw) > 4096 {
		return gate, errors.New("oversized storage maintenance gate")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return gate, errors.New("invalid storage maintenance gate")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || fields[name] != nil {
			return gate, errors.New("duplicate or invalid storage maintenance key")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return gate, errors.New("invalid storage maintenance value")
		}
		fields[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return gate, errors.New("invalid storage maintenance gate")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return gate, errors.New("trailing storage maintenance value")
	}
	if len(fields) != 4 {
		return gate, errors.New("invalid storage maintenance gate")
	}
	for _, key := range []string{"schema", "held", "delivery_held", "operation"} {
		if _, ok := fields[key]; !ok {
			return gate, errors.New("incomplete storage maintenance gate")
		}
	}
	if json.Unmarshal(raw, &gate) != nil || gate.Schema != 1 || string(fields["held"]) == "null" || string(fields["delivery_held"]) == "null" {
		return gate, errors.New("invalid storage maintenance gate")
	}
	if gate.Held {
		if gate.Operation == nil || !emergencyOperation.MatchString(*gate.Operation) {
			return gate, errors.New("invalid storage maintenance owner")
		}
	} else if gate.DeliveryHeld || gate.Operation != nil {
		return gate, errors.New("inconsistent storage maintenance gate")
	}
	return gate, nil
}
func (state *EmergencyStatus) maintenance(gate emergencyMaintenance) {
	state.MaintenanceHeld = gate.Held
	state.DeliveryHeld = gate.DeliveryHeld
	state.MaintenanceOperation = gate.Operation
	state.MaintenanceMessage = ""
	if gate.Held {
		state.MaintenanceMessage = "Host lifecycle maintenance holds new emergency removals"
		if gate.DeliveryHeld {
			state.MaintenanceMessage += " and log delivery; queued WAL is retained"
		}
	}
}
