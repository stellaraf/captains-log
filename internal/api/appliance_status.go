package api

import (
	"bytes"
	"crypto/fips140"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

const applianceStatusMaxAge = 90 * time.Second

type hostSecurity struct {
	Status             string `json:"status"`
	FIPSKernel         bool   `json:"fips_kernel"`
	FIPSToolPassed     bool   `json:"fips_tool_passed"`
	CryptoPolicy       string `json:"crypto_policy"`
	SELinux            string `json:"selinux"`
	Firewall           string `json:"firewall"`
	Audit              string `json:"audit"`
	HostControlsOK     bool   `json:"host_controls_ok"`
	KernelCryptoStatus string `json:"kernel_crypto_status,omitempty"`
}
type hostStorageGrowth struct {
	PresentedDiskBytes   uint64   `json:"presented_disk_bytes"`
	UnallocatedDiskBytes uint64   `json:"unallocated_disk_bytes"`
	RequiredStages       []string `json:"required_stages"`
	ExpansionNeeded      bool     `json:"expansion_needed"`
}

// Growth is optional for older publishers, but a present observation must be
// complete. Missing/null booleans or sizes must not become measured false/zero.
func (growth *hostStorageGrowth) UnmarshalJSON(data []byte) error {
	var wire struct {
		PresentedDiskBytes   *uint64   `json:"presented_disk_bytes"`
		UnallocatedDiskBytes *uint64   `json:"unallocated_disk_bytes"`
		RequiredStages       *[]string `json:"required_stages"`
		ExpansionNeeded      *bool     `json:"expansion_needed"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.PresentedDiskBytes == nil || wire.UnallocatedDiskBytes == nil ||
		wire.RequiredStages == nil || wire.ExpansionNeeded == nil {
		return errors.New("incomplete host storage growth observation")
	}
	*growth = hostStorageGrowth{PresentedDiskBytes: *wire.PresentedDiskBytes, UnallocatedDiskBytes: *wire.UnallocatedDiskBytes,
		RequiredStages: *wire.RequiredStages, ExpansionNeeded: *wire.ExpansionNeeded}
	return nil
}

type hostStorage struct {
	Status                  string             `json:"status"`
	LUKS2Verified           bool               `json:"luks2_verified"`
	Filesystem              string             `json:"filesystem"`
	CapacityBytes           uint64             `json:"capacity_bytes"`
	VGFreeBytes             uint64             `json:"vg_free_bytes"`
	EncryptedMembers        uint64             `json:"encrypted_members"`
	Growth                  *hostStorageGrowth `json:"growth,omitempty"`
	FilesystemGeometryBytes *uint64            `json:"filesystem_geometry_bytes,omitempty"`
	LogicalVolumeBytes      *uint64            `json:"logical_volume_bytes,omitempty"`
}
type hostBaseline struct {
	Status          string            `json:"status"`
	Selected        string            `json:"selected"`
	Assessed        bool              `json:"assessed"`
	ReviewComplete  bool              `json:"review_complete"`
	LastAssessment  string            `json:"last_assessment"`
	ReviewExpiresAt string            `json:"review_expires_at"`
	Counts          map[string]uint64 `json:"counts"`
}
type hostUpdateEvent struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Sequence  uint64 `json:"sequence"`
}
type hostGitHubUpdates struct {
	Repository          string `json:"repository,omitempty"`
	Status              string `json:"status"`
	AutomaticUpdates    bool   `json:"automatic_updates"`
	Configured          bool   `json:"configured"`
	PollIntervalSeconds uint64 `json:"poll_interval_seconds"`
	TimerEnabled        bool   `json:"timer_enabled"`
	TimerActive         bool   `json:"timer_active"`
	PublisherEnrolled   bool   `json:"publisher_enrolled"`
	Fresh               bool   `json:"fresh"`
	CheckedAt           string `json:"checked_at"`
	NextCheckAt         string `json:"next_check_at"`
}
type hostUpdates struct {
	Status                    string             `json:"status"`
	CurrentSequence           uint64             `json:"current_sequence"`
	Components                map[string]string  `json:"components"`
	Transaction               string             `json:"transaction"`
	TransactionSequence       uint64             `json:"transaction_sequence"`
	Finalization              string             `json:"finalization"`
	MaintenanceReleasePending bool               `json:"maintenance_release_pending"`
	MaintenanceActive         bool               `json:"maintenance_active"`
	RecoveryAction            string             `json:"recovery_action"`
	OSTransaction             string             `json:"os_transaction"`
	OSFinalization            string             `json:"os_finalization"`
	RebootPending             bool               `json:"reboot_pending"`
	OSUpdatesConfigured       bool               `json:"os_updates_configured"`
	OSTimerEnabled            bool               `json:"os_timer_enabled"`
	OSTimerStatus             string             `json:"os_timer_status"`
	History                   []hostUpdateEvent  `json:"history"`
	GitHub                    *hostGitHubUpdates `json:"github,omitempty"`
	HostRefusal               *hostUpdateRefusal `json:"host_refusal,omitempty"`
}
type hostUpdateRefusal struct {
	Reason   string `json:"reason"`
	Resource string `json:"resource"`
	Sequence uint64 `json:"sequence"`
}
type applianceStatus struct {
	Schema     int           `json:"schema"`
	ObservedAt time.Time     `json:"observed_at"`
	Security   *hostSecurity `json:"security"`
	Storage    *hostStorage  `json:"storage"`
	Baseline   *hostBaseline `json:"baseline"`
	Updates    *hostUpdates  `json:"updates"`
}

func trustedStatusInfo(info os.FileInfo, owner uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == owner && info.Mode().Perm()&0022 == 0
}

// owner is always zero in production. Tests use their invoking UID without
// weakening the root-owned host-to-container trust boundary.
func readApplianceStatus(path string, now time.Time, owner uint32) (applianceStatus, error) {
	var value applianceStatus
	fail := errors.New("host observation is unavailable, unsafe, stale or invalid")
	if !filepath.IsAbs(path) {
		return value, fail
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (!trustedStatusInfo(info, 0) && !trustedStatusInfo(info, owner)) {
			return value, fail
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !trustedStatusInfo(info, owner) {
		return value, fail
	}
	f, err := os.Open(path)
	if err != nil {
		return value, fail
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !trustedStatusInfo(opened, owner) || opened.Size() > 64*1024 {
		return value, fail
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(data) > 64*1024 || !uniqueStatusJSON(json.NewDecoder(bytes.NewReader(data)), 0) {
		return applianceStatus{}, fail
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return applianceStatus{}, fail
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || value.Schema != 1 || value.ObservedAt.IsZero() ||
		now.Sub(value.ObservedAt) > applianceStatusMaxAge || value.ObservedAt.Sub(now) > 5*time.Second ||
		value.Security == nil || value.Storage == nil || value.Baseline == nil || value.Updates == nil {
		return applianceStatus{}, fail
	}
	for _, state := range []string{value.Security.Status, value.Storage.Status, value.Baseline.Status, value.Updates.Status} {
		if state != "observed" && state != "unavailable" {
			return applianceStatus{}, fail
		}
	}
	if !validHostObservation(value, now) {
		return applianceStatus{}, fail
	}
	return value, nil
}

// Ambiguous duplicate members and deeply nested input are not a valid snapshot.
func uniqueStatusJSON(decoder *json.Decoder, depth int) bool {
	if depth > 16 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return true
	}
	if delimiter != '{' && delimiter != '[' {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
		}
		if !uniqueStatusJSON(decoder, depth+1) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && ((delimiter == '{' && end == json.Delim('}')) || (delimiter == '[' && end == json.Delim(']')))
}

func validHostObservation(value applianceStatus, now time.Time) bool {
	security, storage, baseline, updates := value.Security, value.Storage, value.Baseline, value.Updates
	if security.Status == "observed" {
		if !slices.Contains([]string{"", "no_failure_observed", "failed", "unavailable"}, security.KernelCryptoStatus) ||
			security.HostControlsOK && security.KernelCryptoStatus != "" && security.KernelCryptoStatus != "no_failure_observed" {
			return false
		}
		if !slices.Contains([]string{"FIPS", "DEFAULT", "LEGACY", "FUTURE", "unavailable"}, security.CryptoPolicy) ||
			!slices.Contains([]string{"Enforcing", "Permissive", "Disabled", "unavailable"}, security.SELinux) ||
			!slices.Contains([]string{"active", "inactive", "failed", "unavailable"}, security.Firewall) ||
			!slices.Contains([]string{"active", "inactive", "failed", "unavailable"}, security.Audit) {
			return false
		}
		if security.HostControlsOK && !(security.FIPSKernel && security.FIPSToolPassed && security.CryptoPolicy == "FIPS" && security.SELinux == "Enforcing" && security.Firewall == "active" && security.Audit == "active") {
			return false
		}
	}
	if storage.Status == "observed" && (!storage.LUKS2Verified || storage.Filesystem != "xfs" || storage.CapacityBytes == 0 || storage.EncryptedMembers == 0) {
		return false
	}
	if storage.Status == "observed" && (storage.FilesystemGeometryBytes != nil || storage.LogicalVolumeBytes != nil) {
		if storage.FilesystemGeometryBytes == nil || storage.LogicalVolumeBytes == nil ||
			*storage.FilesystemGeometryBytes < storage.CapacityBytes || *storage.FilesystemGeometryBytes > *storage.LogicalVolumeBytes {
			return false
		}
	}
	if storage.Status == "observed" && storage.Growth != nil {
		growth := storage.Growth
		if growth.PresentedDiskBytes == 0 || growth.UnallocatedDiskBytes > growth.PresentedDiskBytes ||
			growth.RequiredStages == nil || growth.ExpansionNeeded != (len(growth.RequiredStages) > 0) || len(growth.RequiredStages) > 5 {
			return false
		}
		// The installed planner always completes a contiguous suffix ending in XFS.
		stages := []string{"partition", "luks", "pv", "lv", "xfs"}
		if len(growth.RequiredStages) > 0 && !slices.Equal(growth.RequiredStages, stages[len(stages)-len(growth.RequiredStages):]) {
			return false
		}
	}
	if baseline.Status == "observed" {
		if !slices.Contains([]string{"cis-level2", "unified", "stig"}, baseline.Selected) || baseline.ReviewComplete && !baseline.Assessed {
			return false
		}
		if baseline.Assessed {
			if observed, err := time.Parse(time.RFC3339Nano, baseline.LastAssessment); err != nil || observed.After(now.Add(5*time.Second)) {
				return false
			}
		}
		if baseline.ReviewComplete {
			if expires, err := time.Parse(time.RFC3339Nano, baseline.ReviewExpiresAt); err != nil || !expires.After(now) {
				return false
			}
		}
		for key := range baseline.Counts {
			if !slices.Contains([]string{"pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed"}, key) {
				return false
			}
		}
	}
	states := []string{"none", "preflight", "preflight_failed", "preparing", "activating", "checking", "committed", "rolling_back", "rolled_back", "recovery_required", "updating", "postcheck", "failed", "complete", "reboot_preparing", "reboot_requested", "reboot_aborted"}
	if updates.Status == "observed" {
		if channel := updates.GitHub; channel != nil {
			if !slices.Contains([]string{"not_connected", "unavailable", "awaiting_first_check", "awaiting_enrollment", "stale", "disabled", "checking", "no_release", "up_to_date", "downloading", "installing", "installed", "blocked", "failed"}, channel.Status) {
				return false
			}
			if channel.Repository != "" && (!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`).MatchString(channel.Repository) || channel.PollIntervalSeconds != 900) {
				return false
			}
			if channel.CheckedAt != "" {
				checked, err := time.Parse(time.RFC3339Nano, channel.CheckedAt)
				if err != nil || channel.Fresh && (now.Sub(checked) > 1860*time.Second || checked.After(now.Add(5*time.Second))) {
					return false
				}
			} else if channel.Fresh {
				return false
			}
			if channel.NextCheckAt != "" {
				if _, err := time.Parse(time.RFC3339Nano, channel.NextCheckAt); err != nil {
					return false
				}
			}
			if channel.AutomaticUpdates && !(channel.Repository != "" && channel.Configured && channel.TimerEnabled && channel.TimerActive && channel.PublisherEnrolled && channel.Fresh && slices.Contains([]string{"checking", "no_release", "up_to_date", "downloading", "installing", "installed"}, channel.Status)) {
				return false
			}
			if channel.AutomaticUpdates && (updates.MaintenanceActive || updates.MaintenanceReleasePending) {
				return false
			}
		}
		if !slices.Contains(states, updates.Transaction) || !slices.Contains(states, updates.OSTransaction) ||
			!slices.Contains([]string{"none", "pending", "failed", "complete"}, updates.Finalization) ||
			!slices.Contains([]string{"none", "pending", "failed", "complete"}, updates.OSFinalization) ||
			!slices.Contains([]string{"enabled", "disabled", "masked", "static", "unavailable"}, updates.OSTimerStatus) ||
			!slices.Contains([]string{"", "nebulalog update finalize", "nebulalog update reboot-complete", "nebulalog update os-recover", "nebulalog update recover"}, updates.RecoveryAction) {
			return false
		}
		if refusal := updates.HostRefusal; refusal != nil {
			if refusal.Reason != "qualified_migration_required" || refusal.Sequence == 0 || refusal.Sequence != updates.TransactionSequence ||
				!regexp.MustCompile(`^(share/defaults/[a-z0-9.-]+|share/templates/(keycloak/realm\.json|quadlet/nebulalog\.network)|lib/nebulalog_manager/[a-z_]+\.py|lib/nebulalog_adapters/[a-z_]+\.py|bin/[a-z-]+|share/templates/systemd/[a-z0-9@._/-]+|share/templates/quadlet/[a-z0-9.-]+|share/templates/httpd/nebulalog\.conf\.in)$`).MatchString(refusal.Resource) || strings.Contains(refusal.Resource, "..") || len(refusal.Resource) > 160 {
				return false
			}
		}
		for name, version := range updates.Components {
			if !slices.Contains([]string{"nebulalog", "keycloak", "postgresql", "clickhouse", "scap", "baseline", "host"}, name) || !regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}$`).MatchString(version) {
				return false
			}
		}
	}
	if len(updates.History) > 20 {
		return false
	}
	for _, event := range updates.History {
		parts := strings.Split(event.Action, ".")
		if len(parts) != 2 || !slices.Contains([]string{"update", "os"}, parts[0]) ||
			(!slices.Contains(states, parts[1]) && !slices.Contains([]string{"operator_rollback", "finalized", "finalization_failed", "finalization_health_failed", "reboot_health_failed", "reboot_verified", "recovered"}, parts[1])) {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
			return false
		}
	}
	return true
}

func (s *Server) hostStatus() (applianceStatus, error) {
	return readApplianceStatus(s.Config.ApplianceStatusPath, time.Now(), 0)
}

func (s *Server) security(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.hostStatus()
	var observed *applianceStatus
	if err == nil {
		observed = &snapshot
	}
	respond(w, http.StatusOK, securityResponse(observed, s.Config.ApplianceStatusPath != ""))
}

func securityResponse(snapshot *applianceStatus, configured bool) map[string]any {
	response := map[string]any{"deployment": "development", "status": "unavailable", "fips": "unverified",
		"application_crypto_fips_enabled": fips140.Enabled(), "luks": "unverified", "selinux": "unverified",
		"baseline": "unassessed", "auth": "Keycloak OIDC / PKCE", "mfa": "requires runtime authentication evidence",
		"certification": "not asserted", "message": "Host observations are not connected to this deployment."}
	if configured {
		response["deployment"] = "appliance"
		response["message"] = "Host observations are missing, stale or unsafe. Check the appliance status publisher."
	}
	if snapshot != nil {
		response["deployment"], response["status"], response["observed_at"] = "appliance", "observed", snapshot.ObservedAt
		response["host"], response["storage"], response["baseline_evidence"] = snapshot.Security, snapshot.Storage, snapshot.Baseline
		response["message"] = "Read-only measured host observations. Certification and complete release qualification are not asserted."
		if snapshot.Security.Status == "observed" {
			response["selinux"] = snapshot.Security.SELinux
			if snapshot.Security.FIPSKernel && snapshot.Security.FIPSToolPassed && snapshot.Security.CryptoPolicy == "FIPS" {
				response["fips"] = "host_enabled"
				if snapshot.Security.KernelCryptoStatus == "unavailable" {
					response["fips"] = "diagnostics_unavailable"
				}
			}
			if snapshot.Security.KernelCryptoStatus == "failed" {
				response["fips"] = "self_test_failed"
			}
		}
		if snapshot.Storage.Status == "observed" && snapshot.Storage.LUKS2Verified {
			response["luks"] = "verified_data_volumes"
		}
		response["luks_scope"] = "Enrolled data volumes only; root disk encryption is not inferred."
		if snapshot.Baseline.Status == "observed" && snapshot.Baseline.Assessed {
			response["baseline"] = "assessed_requires_review"
			if snapshot.Baseline.ReviewComplete {
				response["baseline"] = "assessed_and_reviewed"
			}
		}
	}
	return response
}

func (s *Server) updates(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.hostStatus()
	var observed *applianceStatus
	if err == nil {
		observed = &snapshot
	}
	respond(w, http.StatusOK, updatesResponse(observed, s.Config.ApplianceStatusPath != ""))
}

func updatesResponse(snapshot *applianceStatus, configured bool) map[string]any {
	response := map[string]any{"status": "not_connected", "automatic_updates": false, "control": "read_only",
		"message": "Host update observations are not connected to this deployment."}
	if configured {
		response["status"] = "unavailable"
		response["message"] = "Host observations are missing, stale or unsafe. Check the appliance status publisher."
	}
	if snapshot != nil && snapshot.Updates.Status == "observed" {
		response["status"], response["observed_at"], response["manager"] = "observed", snapshot.ObservedAt, snapshot.Updates
		response["message"] = "Read-only update observations. Application releases and OS maintenance have separate schedules."
		if channel := snapshot.Updates.GitHub; channel != nil {
			response["github"] = channel
			response["automatic_updates"] = channel.AutomaticUpdates
			if channel.AutomaticUpdates {
				response["message"] = "GitHub Releases are checked every 15 minutes. Compatible stable application and component updates install automatically after integrity and health checks."
			}
		}
	}
	return response
}

// Capacity detection is independent of permission and capability to change a
// disk. Never turn absent host evidence into a negative growth measurement.
func hostStorageResponse(snapshot *applianceStatus, configured bool) map[string]any {
	response := map[string]any{"host_storage": "not_connected", "expansion_available": nil,
		"storage_control": "unavailable", "host_observation": nil,
		"storage_control_message": "Host storage observations are not connected to this deployment."}
	if configured {
		response["host_storage"] = "unavailable"
		response["storage_control_message"] = "Host storage observations are missing, stale or unsafe. Refresh after the publisher recovers."
	}
	if snapshot != nil && snapshot.Storage != nil && snapshot.Storage.Status == "observed" {
		response["host_storage"] = "observed"
		response["host_observation"] = map[string]any{"observed_at": snapshot.ObservedAt,
			"expires_at": snapshot.ObservedAt.Add(applianceStatusMaxAge), "storage": snapshot.Storage}
		response["storage_control"] = "read_only"
		response["storage_control_message"] = "Measured encrypted data-pool observations. Storage changes require a fresh reviewed host plan; browser execution is not connected."
		if snapshot.Storage.Growth != nil {
			response["growth_scope"] = "designated_disk_and_pool"
			// Disk geometry describes the enrolled designated disk. Free VG space
			// and the LV/filesystem describe the whole pool; resized additional
			// disks are not inspected by this planner. A no-op cannot rule out their growth.
			if snapshot.Storage.EncryptedMembers == 1 || snapshot.Storage.Growth.ExpansionNeeded {
				response["expansion_available"] = snapshot.Storage.Growth.ExpansionNeeded
			}
			if snapshot.Storage.EncryptedMembers > 1 {
				response["additional_disk_growth"] = "not_measured"
			}
		}
	}
	return response
}
