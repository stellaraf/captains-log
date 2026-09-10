package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDisableDoesNotRequireUsableCertificateMappersOrMFA(t *testing.T) {
	for _, mode := range []string{"expired", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			m, f := newFake(t)
			s := setup(t)
			s.MetadataXML = fixtureAt(t, time.Now().Add(-3*time.Hour), time.Now().Add(-time.Hour))
			data, err := parseMetadata(s.MetadataXML, false, time.Now().Add(-2*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			original := m.desired(s, data)
			original.Enabled = true
			original.Config["preserve-custom-setting"] = "value"
			original.Extra = map[string]any{"hideOnLogin": true, "internalId": "synthetic-internal-id", "updateProfileFirstLoginMode": "missing", "addReadTokenRoleOnCreate": true, "futureField": map[string]any{"sequence": json.Number("9007199254740993"), "label": "keep"}}
			if mode == "malformed" {
				original.Config["signingCertificate"] = "not-a-certificate"
			}
			f.providers[s.Alias] = original
			f.otpRequired = false
			p, err := m.SetEnabled(context.Background(), s.Alias, false)
			if err != nil || p.Enabled || !p.Configured || !p.Managed {
				t.Fatal(p, err)
			}
			got := f.providers[s.Alias]
			if got.Enabled || got.Config["nebulalog.operation"] == "" {
				t.Fatal("disable was not persisted")
			}
			delete(got.Config, "nebulalog.operation")
			got.Enabled = original.Enabled
			if !reflect.DeepEqual(got, original) {
				t.Fatal("disable replaced stored configuration")
			}
			for _, call := range f.calls {
				if strings.Contains(call, "/mappers") || strings.Contains(call, "/authentication/flows/") {
					t.Fatal("emergency disable consulted admission-time dependencies", call)
				}
			}
		})
	}
}

func seedState(t *testing.T, m *Manager, f *fakeKC) Setup {
	t.Helper()
	s := setup(t)
	if _, err := m.Save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	return s
}

func TestEnablePreservesConfigurationAndValidatesBeforeAndAfter(t *testing.T) {
	m, f := newFake(t)
	s := seedState(t, m, f)
	original := f.providers[s.Alias]
	original.Extra = map[string]any{"hideOnLogin": true, "internalId": "synthetic-internal-id", "authenticateByDefault": false, "addReadTokenRoleOnCreate": false, "organizationId": nil}
	f.providers[s.Alias] = original
	writes := []bool{}
	f.putHook = func(p representation) (int, bool) {
		writes = append(writes, p.Enabled)
		return http.StatusNoContent, true
	}
	p, err := m.SetEnabled(context.Background(), s.Alias, true)
	if err != nil || !p.Enabled || p.ExternalLoginTested {
		t.Fatal(p, err)
	}
	if !reflect.DeepEqual(writes, []bool{false, true}) {
		t.Fatal("enable did not occur last", writes)
	}
	got := f.providers[s.Alias]
	if got.Config["nebulalog.operation"] == original.Config["nebulalog.operation"] {
		t.Fatal("operation identity reused")
	}
	got.Config["nebulalog.operation"] = original.Config["nebulalog.operation"]
	got.Enabled = original.Enabled
	if !reflect.DeepEqual(got, original) {
		t.Fatal("enable changed stored configuration")
	}
	checks := 0
	for _, call := range f.calls {
		if strings.HasSuffix(call, "/mappers") {
			if !strings.HasPrefix(call, "GET ") {
				t.Fatal("state change mutated mappers", call)
			}
			checks++
		}
	}
	if checks != 3 {
		t.Fatal("expected original, disabled and enabled configuration checks", checks)
	}
}

func TestEnableRejectsInvalidStoredConfigurationWithoutMutation(t *testing.T) {
	for _, mode := range []string{"OTP", "role", "signature", "expired", "token grant", "default authentication", "organization"} {
		t.Run(mode, func(t *testing.T) {
			m, f := newFake(t)
			s := seedState(t, m, f)
			switch mode {
			case "OTP":
				f.otpRequired = false
			case "role":
				f.mappers[s.Alias][0].Config["role"] = "realm-admin"
			case "signature":
				f.providers[s.Alias].Config["validateSignature"] = "false"
			case "token grant", "default authentication", "organization":
				p := f.providers[s.Alias]
				key, value := "addReadTokenRoleOnCreate", any(true)
				if mode == "default authentication" {
					key = "authenticateByDefault"
				}
				if mode == "organization" {
					key, value = "organizationId", "other-organization"
				}
				p.Extra = map[string]any{key: value}
				f.providers[s.Alias] = p
			case "expired":
				data, err := parseMetadata(fixtureAt(t, time.Now().Add(-3*time.Hour), time.Now().Add(-time.Hour)), false, time.Now().Add(-2*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				f.providers[s.Alias].Config["signingCertificate"] = strings.Join(data.keys, ",")
			}
			if _, err := m.SetEnabled(context.Background(), s.Alias, true); !IsKind(err, "conflict") {
				t.Fatal(err)
			}
			for _, call := range f.calls {
				if strings.HasPrefix(call, "PUT ") {
					t.Fatal("invalid configuration was mutated", call)
				}
			}
			if f.providers[s.Alias].Enabled {
				t.Fatal("invalid configuration enabled")
			}
		})
	}
}

func TestFailedEnableVerifiesDisabledCleanup(t *testing.T) {
	for _, mode := range []string{"ambiguous response", "MFA drift", "role drift", "configuration drift"} {
		t.Run(mode, func(t *testing.T) {
			m, f := newFake(t)
			s := seedState(t, m, f)
			f.putHook = func(p representation) (int, bool) {
				if p.Enabled {
					switch mode {
					case "ambiguous response":
						return http.StatusInternalServerError, true // persisted despite failed response
					case "MFA drift":
						f.otpRequired = false
					case "role drift":
						f.mappers[s.Alias][0].Config["role"] = "realm-admin"
					case "configuration drift":
						p.Config["idpEntityId"] = "urn:changed-by-other-actor"
					}
				}
				return http.StatusNoContent, true
			}
			_, err := m.SetEnabled(context.Background(), s.Alias, true)
			if err == nil || !strings.Contains(err.Error(), "verified disabled") || f.providers[s.Alias].Enabled {
				t.Fatal("failed enable did not fail closed", err)
			}
		})
	}
}

func TestEnableCleanupDoesNotClaimUnverifiedDisableOrOverwriteDifferentOwner(t *testing.T) {
	for _, mode := range []string{"ignored disable", "different operation", "different owner"} {
		t.Run(mode, func(t *testing.T) {
			m, f := newFake(t)
			s := seedState(t, m, f)
			enableAttempted := false
			f.putHook = func(p representation) (int, bool) {
				if p.Enabled {
					enableAttempted = true
					if mode == "different operation" {
						p.Config["nebulalog.operation"] = "another-operation"
					}
					if mode == "different owner" {
						p.Config[ownerKey] = "another-owner"
					}
					return http.StatusInternalServerError, true
				}
				if enableAttempted {
					if mode != "ignored disable" {
						t.Error("cleanup overwrote a different owner or operation")
					}
					return http.StatusNoContent, false
				}
				return http.StatusNoContent, true
			}
			_, err := m.SetEnabled(context.Background(), s.Alias, true)
			if err == nil || strings.Contains(err.Error(), "verified disabled") || !f.providers[s.Alias].Enabled {
				t.Fatal("cleanup made a false assurance", err)
			}
			if mode == "ignored disable" && !strings.Contains(err.Error(), "could not be confirmed") {
				t.Fatal(err)
			}
			if mode != "ignored disable" && !IsKind(err, "conflict") {
				t.Fatal(err)
			}
		})
	}
}

func TestStateChangeRejectsMissingUnmanagedAndWrongTypeProviders(t *testing.T) {
	for _, mode := range []string{"missing", "unmanaged", "oidc"} {
		t.Run(mode, func(t *testing.T) {
			m, f := newFake(t)
			if mode != "missing" {
				p := representation{Alias: "okta", ProviderID: "saml", Enabled: true, Config: map[string]string{ownerKey: ownerValue}}
				if mode == "unmanaged" {
					p.Config[ownerKey] = "another-owner"
				} else {
					p.ProviderID = "oidc"
				}
				f.providers["okta"] = p
			}
			if _, err := m.SetEnabled(context.Background(), "okta", false); !IsKind(err, "conflict") {
				t.Fatal(err)
			}
			for _, call := range f.calls {
				if strings.HasPrefix(call, "PUT ") {
					t.Fatal("unexpected mutation", call)
				}
			}
		})
	}
}

func TestStateChangeSharesSaveGateAndRespectsCancellationAndWriteSwitch(t *testing.T) {
	m, f := newFake(t)
	m.config.EnableWrites = false
	if _, err := m.SetEnabled(context.Background(), "okta", false); !IsKind(err, "disabled") {
		t.Fatal(err)
	}
	m.config.EnableWrites = true
	if _, err := m.SetEnabled(context.Background(), "../../master", false); !IsKind(err, "validation") {
		t.Fatal(err)
	}
	m.saveGate <- struct{}{}
	defer func() { <-m.saveGate }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.SetEnabled(ctx, "okta", false); !IsKind(err, "upstream") {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal("state change bypassed gate or write switch")
	}
}
