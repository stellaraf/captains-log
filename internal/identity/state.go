package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"reflect"
	"time"
)

// SetEnabled changes only the enabled state and the operation ownership marker.
// Disable does not require usable metadata, signing certificates, mappers or MFA.
// Enable validates the stored configuration before and after enabling; it never
// updates metadata or mappers. Like Save, it requires a single manager process
// and no concurrent manual edits because Keycloak does not provide CAS updates.
func (m *Manager) SetEnabled(ctx context.Context, alias string, enabled bool) (provider Provider, err error) {
	if !m.config.EnableWrites {
		return Provider{}, problem("disabled", "Identity configuration writes are disabled")
	}
	if err = aliasOK(alias); err != nil {
		return Provider{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, managerTimeout)
	defer cancel()
	select {
	case m.saveGate <- struct{}{}:
		defer func() { <-m.saveGate }()
	case <-ctx.Done():
		return Provider{}, problem("upstream", "Identity configuration operation timed out before starting")
	}
	original, found, err := m.read(ctx, alias)
	if err != nil {
		return Provider{}, err
	}
	if !found {
		return Provider{}, problem("conflict", "Provider is not configured")
	}
	if original.Config[ownerKey] != ownerValue || original.ProviderID != "saml" {
		return Provider{}, problem("conflict", "Provider alias is already owned by another configuration")
	}
	if enabled {
		if err = m.validateSaved(ctx, original); err != nil {
			return Provider{}, err
		}
	}
	latest, exists, err := m.read(ctx, alias)
	if err != nil {
		return Provider{}, err
	}
	if !exists || !reflect.DeepEqual(latest, original) {
		return Provider{}, problem("conflict", "Provider changed while preparing the state change; reload before retrying")
	}
	var operation [16]byte
	if _, err = rand.Read(operation[:]); err != nil {
		return Provider{}, problem("upstream", "Unable to create configuration operation identity")
	}
	operationID := hex.EncodeToString(operation[:])
	desired := original
	desired.Config = make(map[string]string, len(original.Config)+1)
	for key, value := range original.Config {
		desired.Config[key] = value
	}
	desired.Config["nebulalog.operation"] = operationID
	desired.Enabled = false
	// Mark mutation before the request: a timeout can happen after Keycloak has
	// persisted it. Cleanup may act only after rereading this operation's marker.
	defer func() {
		if err != nil {
			err = m.recoverStateChange(alias, operationID, err)
		}
	}()
	if _, err = m.request(ctx, http.MethodPut, instancePath(alias), desired, nil); err != nil {
		return Provider{}, err
	}
	saved, exists, err := m.read(ctx, alias)
	if err != nil {
		return Provider{}, err
	}
	if !exists || !reflect.DeepEqual(saved, desired) {
		return Provider{}, problem("upstream", "Disabled provider state and preserved configuration could not be verified")
	}
	if !enabled {
		// Certificate display must not prevent an emergency disable, including a
		// malformed certificate that cannot be inspected. The disabled state and
		// unchanged configuration have already been independently verified.
		provider, _ = m.public(saved)
		return provider, nil
	}
	if err = m.validateSaved(ctx, saved); err != nil {
		return Provider{}, err
	}
	desired.Enabled = true
	if _, err = m.request(ctx, http.MethodPut, instancePath(alias), desired, nil); err != nil {
		return Provider{}, err
	}
	saved, exists, err = m.read(ctx, alias)
	if err != nil {
		return Provider{}, err
	}
	if !exists || !reflect.DeepEqual(saved, desired) {
		return Provider{}, problem("upstream", "Enabled provider state and preserved configuration could not be verified")
	}
	if err = m.validateSaved(ctx, saved); err != nil {
		return Provider{}, err
	}
	return m.public(saved)
}

func (m *Manager) recoverStateChange(alias, operation string, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	uncertain := problem("upstream", "Provider state change failed; disabled state could not be confirmed. Inspect Keycloak before retrying")
	current, exists, err := m.read(ctx, alias)
	if err != nil {
		return uncertain
	}
	if !exists {
		return problem("upstream", "Provider state change failed; the provider no longer exists")
	}
	if current.ProviderID != "saml" || current.Config[ownerKey] != ownerValue || current.Config["nebulalog.operation"] != operation {
		return problem("conflict", "Provider state change failed; another configuration owns the alias. It was not modified during cleanup")
	}
	current.Enabled = false
	if _, err = m.request(ctx, http.MethodPut, instancePath(alias), current, nil); err != nil {
		return uncertain
	}
	confirmed, exists, err := m.read(ctx, alias)
	if err != nil || !exists || !reflect.DeepEqual(confirmed, current) {
		return uncertain
	}
	return problem("upstream", "Provider state change failed: "+cause.Error()+"; the provider was verified disabled")
}
