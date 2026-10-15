package store

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const StorageMaintenancePath = "/run/nebulalog-storage-maintenance/gate.json"

var errHostStorageGate = errors.New("Host storage maintenance gate is missing, unsafe, invalid or inconsistent; storage work is held")

// Production roles must consume the fixed read-only mount. The one-shot migrate
// and version commands do not start workers or delivery and do not call this.
func ValidateStorageMaintenancePath(path string, required bool) error {
	if required && path != StorageMaintenancePath {
		return errHostStorageGate
	}
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errHostStorageGate
	}
	_, err := readHostStorageGate(path)
	return err
}
func trustedGateInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0022 == 0
}
func readHostStorageGate(path string) (emergencyMaintenance, error) {
	var none emergencyMaintenance
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return none, errHostStorageGate
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !trustedGateInfo(info) {
			return none, errHostStorageGate
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	// Ownership bits alone are insufficient when an incorrectly privileged app
	// could write this directory; kernel access must report it unwritable.
	if err := syscall.Access(filepath.Dir(path), 2); err != syscall.EACCES && err != syscall.EROFS {
		return none, errHostStorageGate
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !trustedGateInfo(info) || info.Size() > 4096 {
		return none, errHostStorageGate
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return none, errHostStorageGate
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || !trustedGateInfo(opened) || opened.Size() > 4096 {
		return none, errHostStorageGate
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return none, errHostStorageGate
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || !trustedGateInfo(after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return none, errHostStorageGate
	}
	gate, err := parseEmergencyMaintenance(raw)
	if err != nil {
		return none, errHostStorageGate
	}
	return gate, nil
}
func (s *Store) readHostMaintenance() (emergencyMaintenance, error) {
	if s.StorageMaintenancePath == "" {
		return emergencyMaintenance{Schema: 1}, nil
	}
	return readHostStorageGate(s.StorageMaintenancePath)
}
func mergeEmergencyMaintenance(host, db emergencyMaintenance) (emergencyMaintenance, error) {
	if host.Held && db.Held && (host.Operation == nil || db.Operation == nil || *host.Operation != *db.Operation) {
		return emergencyMaintenance{}, errHostStorageGate
	}
	result := db
	if host.Held {
		result.Held = true
		result.Operation = host.Operation
	}
	result.DeliveryHeld = host.DeliveryHeld || db.DeliveryHeld
	return result, nil
}

// Call only after the appropriate shared/exclusive application DB lock. A host
// publication before the lock barrier is observed even if the PG snapshot was
// restored to an older idle gate. No database value can clear a host hold.
func (s *Store) effectiveEmergencyMaintenance(ctx context.Context, q emergencyQuerier) (emergencyMaintenance, error) {
	host, err := s.readHostMaintenance()
	if err != nil {
		return emergencyMaintenance{}, err
	}
	db, err := readEmergencyMaintenance(ctx, q)
	if err != nil {
		return emergencyMaintenance{}, err
	}
	return mergeEmergencyMaintenance(host, db)
}
