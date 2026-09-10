package identity

import (
	"bytes"
	"encoding/json"
)

// Keycloak updates the entire identity-provider representation on PUT. Preserve
// fields outside the manager's modeled subset so a state-only change cannot
// reset settings such as hideOnLogin, internalId or future version additions.
// Extra values never appear in the public API. UseNumber preserves integer
// precision and map decoding makes equality independent of JSON object order.
type plainRepresentation representation

func (r *representation) UnmarshalJSON(data []byte) error {
	var value plainRepresentation
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		return err
	}
	known, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(known, &keys); err != nil {
		return err
	}
	for key := range keys {
		delete(fields, key)
	}
	*r = representation(value)
	if len(fields) > 0 {
		r.Extra = fields
	}
	return nil
}

func (r representation) MarshalJSON() ([]byte, error) {
	known, err := json.Marshal(plainRepresentation(r))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(known, &fields); err != nil {
		return nil, err
	}
	for key, value := range r.Extra {
		if _, modeled := fields[key]; modeled {
			continue // Extra fields cannot override enabled, owner config or alias.
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		fields[key] = encoded
	}
	return json.Marshal(fields)
}
