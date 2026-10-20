package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statusFixture(now time.Time) applianceStatus {
	return applianceStatus{Schema: 1, ObservedAt: now,
		Security: &hostSecurity{Status: "observed", FIPSKernel: true, FIPSToolPassed: true, CryptoPolicy: "FIPS", SELinux: "Enforcing", Firewall: "active", Audit: "active", HostControlsOK: true},
		Storage:  &hostStorage{Status: "observed", LUKS2Verified: true, Filesystem: "xfs", CapacityBytes: 1024, EncryptedMembers: 1},
		Baseline: &hostBaseline{Status: "observed", Selected: "unified", Assessed: true, ReviewComplete: true, LastAssessment: now.Add(-time.Hour).Format(time.RFC3339), ReviewExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Counts: map[string]uint64{"pass": 42}},
		Updates:  &hostUpdates{Status: "observed", CurrentSequence: 7, Components: map[string]string{"nebulalog": "0.1.0"}, Transaction: "committed", TransactionSequence: 7, Finalization: "failed", MaintenanceReleasePending: true, RecoveryAction: "nebulalog update finalize", OSTransaction: "none", OSFinalization: "none", OSTimerStatus: "disabled", History: []hostUpdateEvent{{Timestamp: now.Format(time.RFC3339), Action: "update.committed", Sequence: 7}}}}
}

func TestKernelCryptoObservationOverridesEnabledFIPSMode(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct{ diagnostic, expected string }{
		{"failed", "self_test_failed"}, {"unavailable", "diagnostics_unavailable"},
		{"no_failure_observed", "host_enabled"}, {"", "host_enabled"},
	} {
		t.Run(test.diagnostic, func(t *testing.T) {
			value := statusFixture(now)
			value.Security.KernelCryptoStatus = test.diagnostic
			value.Security.HostControlsOK = test.diagnostic == "" || test.diagnostic == "no_failure_observed"
			if !validHostObservation(value, now) {
				t.Fatal("valid measured observation rejected")
			}
			if got := securityResponse(&value, true)["fips"]; got != test.expected {
				t.Fatalf("FIPS status = %v, want %v", got, test.expected)
			}
		})
	}
	for _, diagnostic := range []string{"failed", "unavailable", "unexpected"} {
		value := statusFixture(now)
		value.Security.KernelCryptoStatus = diagnostic
		if validHostObservation(value, now) {
			t.Fatalf("accepted a healthy claim with kernel diagnostic %q", diagnostic)
		}
	}
}

func statusPath(t *testing.T) string {
	t.Helper()
	// Use a trusted ancestry in the checkout; the system temp root may be 1777.
	directory, err := os.MkdirTemp(".", ".appliance-status-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "status.json")
}

func TestGitHubAutomaticUpdatesRequireFreshTrustedChannelEvidence(t *testing.T) {
	now := time.Now().UTC()
	fixture := func() applianceStatus {
		value := statusFixture(now)
		value.Updates.MaintenanceReleasePending = false
		value.Updates.Finalization = "complete"
		value.Updates.GitHub = &hostGitHubUpdates{Repository: "stellaraf/captains-log", Status: "up_to_date", AutomaticUpdates: true,
			Configured: true, PollIntervalSeconds: 900, TimerEnabled: true, TimerActive: true, PublisherEnrolled: true, Fresh: true,
			CheckedAt: now.Format(time.RFC3339Nano), NextCheckAt: now.Add(15 * time.Minute).Format(time.RFC3339Nano)}
		return value
	}
	value := fixture()
	if !validHostObservation(value, now) || updatesResponse(&value, true)["automatic_updates"] != true {
		t.Fatal("verified automatic channel was not reported")
	}
	for _, mutate := range []func(*applianceStatus){
		func(v *applianceStatus) { v.Updates.GitHub.CheckedAt = now.Add(-time.Hour).Format(time.RFC3339Nano) },
		func(v *applianceStatus) { v.Updates.GitHub.PublisherEnrolled = false },
		func(v *applianceStatus) { v.Updates.GitHub.TimerActive = false },
		func(v *applianceStatus) { v.Updates.GitHub.Status = "blocked" },
		func(v *applianceStatus) { v.Updates.GitHub.PollIntervalSeconds = 86400 },
		func(v *applianceStatus) { v.Updates.MaintenanceReleasePending = true },
		func(v *applianceStatus) { v.Updates.GitHub.Repository = "https://untrusted.invalid/release" },
	} {
		value = fixture()
		mutate(&value)
		if validHostObservation(value, now) {
			t.Fatal("unverified automatic channel was accepted")
		}
	}
}

func TestOSPostcheckRecoveryActionIsAllowlisted(t *testing.T) {
	now := time.Now().UTC()
	value := statusFixture(now)
	value.Updates.RecoveryAction = "nebulalog update os-recover"
	if !validHostObservation(value, now) {
		t.Fatal("installed OS recovery command was rejected")
	}
	value.Updates.RecoveryAction = "nebulalog update os-recover; arbitrary-command"
	if validHostObservation(value, now) {
		t.Fatal("unrecognized recovery action was accepted")
	}
}

func TestInterruptedComponentRecoveryActionIsAllowlisted(t *testing.T) {
	now := time.Now().UTC()
	value := statusFixture(now)
	value.Updates.RecoveryAction = "nebulalog update recover"
	if !validHostObservation(value, now) {
		t.Fatal("installed component recovery command was rejected")
	}
	value.Updates.RecoveryAction = "nebulalog update recover --arbitrary-option"
	if validHostObservation(value, now) {
		t.Fatal("unrecognized recovery action was accepted")
	}
}

func TestKernelRecoveryActionsAreFixedCommands(t *testing.T) {
	now := time.Now().UTC()
	for _, command := range []string{"nebulalog update kernel-retry", "nebulalog update kernel-rollback"} {
		value := statusFixture(now)
		value.Updates.RecoveryAction = command
		if !validHostObservation(value, now) {
			t.Fatalf("installed kernel recovery command rejected: %s", command)
		}
		for _, suffix := range []string{" --force", "; arbitrary-command", "\n"} {
			value.Updates.RecoveryAction = command + suffix
			if validHostObservation(value, now) {
				t.Fatalf("modified recovery command accepted: %q", value.Updates.RecoveryAction)
			}
		}
	}
}

func TestHostUpdateGenerationAndMigrationRefusalAreValidated(t *testing.T) {
	now := time.Now().UTC()
	value := statusFixture(now)
	value.Updates.Components["host"] = "0.0.0-factory.0123456789abcdef"
	value.Updates.HostRefusal = &hostUpdateRefusal{Reason: "qualified_migration_required", Resource: "share/defaults/aide-policy.conf", Sequence: 7}
	value.Updates.History = append(value.Updates.History, hostUpdateEvent{Timestamp: now.Format(time.RFC3339), Action: "update.recovered", Sequence: 7})
	if !validHostObservation(value, now) {
		t.Fatal("measured host update status was rejected")
	}
	value.Updates.HostRefusal.Resource = "/etc/nebulalog/private-secret"
	if validHostObservation(value, now) {
		t.Fatal("unbounded refusal path was accepted")
	}
	value.Updates.HostRefusal.Resource = "share/defaults/../../private-secret"
	if validHostObservation(value, now) {
		t.Fatal("refusal traversal was accepted")
	}
	value.Updates.HostRefusal.Resource = "share/defaults/aide-policy.conf"
	value.Updates.HostRefusal.Sequence = 8
	if validHostObservation(value, now) {
		t.Fatal("unbound refusal sequence was accepted")
	}
}

func writeStatusFixture(t *testing.T, path string, value applianceStatus) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestHostStatusTrustedFreshObservationAndMeasuredResponse(t *testing.T) {
	now, path := time.Now().UTC(), statusPath(t)
	writeStatusFixture(t, path, statusFixture(now))
	value, err := readApplianceStatus(path, now, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	security := securityResponse(&value, true)
	if security["fips"] != "host_enabled" || security["luks"] != "verified_data_volumes" || security["baseline"] != "assessed_and_reviewed" || security["certification"] != "not asserted" {
		t.Fatal(security)
	}
	updates := updatesResponse(&value, true)
	if updates["status"] != "observed" || updates["automatic_updates"] != false || updates["control"] != "read_only" {
		t.Fatal(updates)
	}
	if value.Updates.RecoveryAction != "nebulalog update finalize" || value.Updates.History[0].Sequence != 7 {
		t.Fatal(value.Updates)
	}
}

func TestHostStatusRejectsStaleFutureUnknownIncompleteAndContradictoryEvidence(t *testing.T) {
	now, path := time.Now().UTC(), statusPath(t)
	cases := map[string]func(*applianceStatus){
		"stale":              func(v *applianceStatus) { v.ObservedAt = now.Add(-91 * time.Second) },
		"future":             func(v *applianceStatus) { v.ObservedAt = now.Add(6 * time.Second) },
		"schema":             func(v *applianceStatus) { v.Schema = 2 },
		"missing":            func(v *applianceStatus) { v.Security = nil },
		"fips flags":         func(v *applianceStatus) { v.Security.CryptoPolicy = "DEFAULT" },
		"unknown status":     func(v *applianceStatus) { v.Storage.Status = "certified" },
		"unmeasured storage": func(v *applianceStatus) { v.Storage.CapacityBytes = 0 },
		"expired review":     func(v *applianceStatus) { v.Baseline.ReviewExpiresAt = now.Add(-time.Second).Format(time.RFC3339) },
		"unknown counts":     func(v *applianceStatus) { v.Baseline.Counts["private evidence"] = 1 },
		"unsafe action":      func(v *applianceStatus) { v.Updates.RecoveryAction = "arbitrary command" },
		"history limit":      func(v *applianceStatus) { v.Updates.History = make([]hostUpdateEvent, 21) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			value := statusFixture(now)
			change(&value)
			writeStatusFixture(t, path, value)
			if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err == nil {
				t.Fatal("invalid host evidence accepted")
			}
		})
	}
}

func TestHostStatusRejectsUnsafeOwnershipPermissionsLinksAndBytes(t *testing.T) {
	now, path := time.Now().UTC(), statusPath(t)
	writeStatusFixture(t, path, statusFixture(now))
	if _, err := readApplianceStatus(path, now, uint32(os.Getuid()+1)); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err == nil {
		t.Fatal("writable status accepted")
	}
	os.Chmod(path, 0644)
	for _, data := range []string{`{`, strings.Repeat("x", 65537), `{"schema":1,"secret":"should not be exposed"}`, "null"} {
		os.WriteFile(path, []byte(data), 0644)
		if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err == nil {
			t.Fatal("invalid status accepted")
		}
	}
	writeStatusFixture(t, path, statusFixture(now))
	valid, _ := os.ReadFile(path)
	for _, invalid := range [][]byte{append([]byte(`{"schema":99,`), valid[1:]...), append(valid, []byte(` {}`)...)} {
		os.WriteFile(path, invalid, 0644)
		if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err == nil {
			t.Fatal("ambiguous or trailing JSON accepted")
		}
	}
	writeStatusFixture(t, path, statusFixture(now))
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := readApplianceStatus(path+".link", now, uint32(os.Getuid())); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(filepath.Dir(path), 0777)
	if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err == nil {
		t.Fatal("writable parent accepted")
	}
}

func TestHostUnavailableSectionsNeverClaimHealthyControls(t *testing.T) {
	now, path := time.Now().UTC(), statusPath(t)
	value := applianceStatus{Schema: 1, ObservedAt: now, Security: &hostSecurity{Status: "unavailable"}, Storage: &hostStorage{Status: "unavailable"}, Baseline: &hostBaseline{Status: "unavailable"}, Updates: &hostUpdates{Status: "unavailable"}}
	writeStatusFixture(t, path, value)
	value, err := readApplianceStatus(path, now, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	response := securityResponse(&value, true)
	if response["fips"] != "unverified" || response["luks"] != "unverified" || response["baseline"] != "unassessed" {
		t.Fatal(response)
	}
	if updatesResponse(&value, true)["status"] != "unavailable" {
		t.Fatal("missing update observations accepted")
	}
}

func TestHostStatusAbsentOrUnsafeHandlerStaysUnavailable(t *testing.T) {
	for _, path := range []string{"", statusPath(t)} {
		s := &Server{Config: Config{ApplianceStatusPath: path}}
		for name, handler := range map[string]func(*httptest.ResponseRecorder){
			"security": func(w *httptest.ResponseRecorder) { s.security(w, httptest.NewRequest("GET", "/api/security", nil)) },
			"updates":  func(w *httptest.ResponseRecorder) { s.updates(w, httptest.NewRequest("GET", "/api/updates", nil)) },
		} {
			t.Run(name+path, func(t *testing.T) {
				w := httptest.NewRecorder()
				handler(w)
				if w.Code != 200 || strings.Contains(w.Body.String(), `"status":"observed"`) || strings.Contains(w.Body.String(), `"automatic_updates":true`) {
					t.Fatal(w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestHostStorageReportsMeasuredGrowthSeparatelyFromExecution(t *testing.T) {
	for _, configured := range []bool{false, true} {
		response := hostStorageResponse(nil, configured)
		if response["expansion_available"] != nil || response["storage_control"] != "unavailable" || response["host_observation"] != nil {
			t.Fatal(response)
		}
	}
	snapshot := statusFixture(time.Now().UTC())
	response := hostStorageResponse(&snapshot, true)
	if response["host_storage"] != "observed" || response["expansion_available"] != nil || response["storage_control"] != "read_only" {
		t.Fatal(response)
	}
	for _, expanded := range []bool{false, true} {
		snapshot.Storage.Growth = &hostStorageGrowth{PresentedDiskBytes: 4096, ExpansionNeeded: expanded, RequiredStages: []string{}}
		if expanded {
			snapshot.Storage.Growth.RequiredStages = []string{"partition", "luks", "pv", "lv", "xfs"}
		}
		if !validHostObservation(snapshot, time.Now()) {
			t.Fatal("valid measured growth rejected")
		}
		response = hostStorageResponse(&snapshot, true)
		if response["expansion_available"] != expanded || response["storage_control"] != "read_only" {
			t.Fatal(response)
		}
	}
	snapshot.Storage.Status = "unavailable"
	response = hostStorageResponse(&snapshot, true)
	if response["expansion_available"] != nil || response["host_observation"] != nil {
		t.Fatal(response)
	}
}

func TestHostStorageRejectsInvalidGrowthEvidence(t *testing.T) {
	for name, growth := range map[string]hostStorageGrowth{
		"missing size":         {},
		"impossible size":      {PresentedDiskBytes: 10, UnallocatedDiskBytes: 11},
		"unmeasured needed":    {PresentedDiskBytes: 10, ExpansionNeeded: true},
		"contradictory stages": {PresentedDiskBytes: 10, RequiredStages: []string{"xfs"}},
		"unknown stage":        {PresentedDiskBytes: 10, ExpansionNeeded: true, RequiredStages: []string{"shrink"}},
		"duplicate stage":      {PresentedDiskBytes: 10, ExpansionNeeded: true, RequiredStages: []string{"pv", "pv"}},
		"reversed stages":      {PresentedDiskBytes: 10, ExpansionNeeded: true, RequiredStages: []string{"xfs", "pv"}},
		"incomplete stages":    {PresentedDiskBytes: 10, ExpansionNeeded: true, RequiredStages: []string{"partition"}},
		"skipped stage":        {PresentedDiskBytes: 10, ExpansionNeeded: true, RequiredStages: []string{"pv", "xfs"}},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := statusFixture(time.Now().UTC())
			snapshot.Storage.Growth = &growth
			if validHostObservation(snapshot, time.Now()) {
				t.Fatal("invalid growth accepted")
			}
		})
	}
}

func TestHostStorageRejectsPartialOrNullGrowthWithoutBreakingOldSnapshots(t *testing.T) {
	now, path := time.Now().UTC(), statusPath(t)
	snapshot := statusFixture(now)
	writeStatusFixture(t, path, snapshot)
	if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err != nil {
		t.Fatal("older snapshot without growth should remain valid", err)
	}
	complete := map[string]any{"presented_disk_bytes": uint64(4096), "unallocated_disk_bytes": uint64(0),
		"required_stages": []string{}, "expansion_needed": false}
	data, _ := json.Marshal(snapshot)
	var wire map[string]any
	json.Unmarshal(data, &wire)
	for _, field := range []string{"presented_disk_bytes", "unallocated_disk_bytes", "required_stages", "expansion_needed"} {
		for _, missing := range []bool{true, false} {
			t.Run(field+map[bool]string{true: " absent", false: " null"}[missing], func(t *testing.T) {
				growth := map[string]any{}
				for name, value := range complete {
					growth[name] = value
				}
				if missing {
					delete(growth, field)
				} else {
					growth[field] = nil
				}
				wire["storage"].(map[string]any)["growth"] = growth
				data, _ := json.Marshal(wire)
				if err := os.WriteFile(path, data, 0644); err != nil {
					t.Fatal(err)
				}
				if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err == nil {
					t.Fatal("partial growth became a measured zero/false")
				}
			})
		}
	}
	wire["storage"].(map[string]any)["growth"] = complete
	data, _ = json.Marshal(wire)
	os.WriteFile(path, data, 0644)
	if _, err := readApplianceStatus(path, now, uint32(os.Getuid())); err != nil {
		t.Fatal("complete measured zero/false should remain valid", err)
	}
}

func TestHostStorageMultiPVScopeAndObservationExpiry(t *testing.T) {
	now := time.Now().UTC()
	snapshot := statusFixture(now)
	snapshot.Storage.CapacityBytes = 12 * 1024 * 1024 * 1024
	snapshot.Storage.EncryptedMembers = 2
	snapshot.Storage.Growth = &hostStorageGrowth{PresentedDiskBytes: 8 * 1024 * 1024 * 1024, RequiredStages: []string{}}
	if !validHostObservation(snapshot, now) {
		t.Fatal("pool capacity may exceed the designated disk in a multi-PV pool")
	}
	response := hostStorageResponse(&snapshot, true)
	if response["expansion_available"] != nil || response["growth_scope"] != "designated_disk_and_pool" || response["additional_disk_growth"] != "not_measured" {
		t.Fatal("unmeasured additional-disk geometry was treated as no growth", response)
	}
	observation := response["host_observation"].(map[string]any)
	if observation["expires_at"] != now.Add(applianceStatusMaxAge) {
		t.Fatal("browser observation must expire with its host measurement", observation)
	}
	snapshot.Storage.Growth.RequiredStages = []string{"lv", "xfs"}
	snapshot.Storage.Growth.ExpansionNeeded = true
	if !validHostObservation(snapshot, now) || hostStorageResponse(&snapshot, true)["expansion_available"] != true {
		t.Fatal("measured whole-pool free extents must remain detectable")
	}
}

func TestHostStorageUsableCapacityAndGeometryRemainDistinct(t *testing.T) {
	now := time.Now().UTC()
	snapshot := statusFixture(now)
	geometry, volume := snapshot.Storage.CapacityBytes+1024, snapshot.Storage.CapacityBytes+2048
	snapshot.Storage.FilesystemGeometryBytes, snapshot.Storage.LogicalVolumeBytes = &geometry, &volume
	if !validHostObservation(snapshot, now) {
		t.Fatal("usable capacity may exclude the internal XFS journal")
	}
	for _, change := range []func(){
		func() { snapshot.Storage.LogicalVolumeBytes = nil },
		func() { snapshot.Storage.LogicalVolumeBytes = &volume; geometry = snapshot.Storage.CapacityBytes - 1 },
		func() { geometry = volume + 1 },
	} {
		change()
		if validHostObservation(snapshot, now) {
			t.Fatal("inconsistent usable/geometry/volume measurement accepted")
		}
	}
}
