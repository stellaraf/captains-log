package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stellaraf/captains-log/internal/store"
)

func TestInitializeStorageRoleRefusesBeforeDatabasesOrMigrationOverrides(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()
	for _, tc := range []struct {
		name                  string
		args                  []string
		operation, gate, want string
	}{
		{"extra arguments", []string{"nebulalog", "initialize-storage", "arbitrary.sql"}, strings.Repeat("a", 64), "", "accepts no arguments"},
		{"missing host intent", []string{"nebulalog", "initialize-storage"}, "", "", "journal-owned"},
		{"missing protected gate", []string{"nebulalog", "initialize-storage"}, strings.Repeat("a", 64), "", "storage maintenance gate"},
		{"alternate gate", []string{"nebulalog", "initialize-storage"}, strings.Repeat("a", 64), "/tmp/not-host-owned", "storage maintenance gate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			t.Setenv("REQUIRE_FIPS", "false")
			t.Setenv("PG_DSN", "")
			t.Setenv("PG_MIGRATION", "/must-never-read-postgres.sql")
			t.Setenv("CH_MIGRATION", "/must-never-read-clickhouse.sql")
			t.Setenv("STORAGE_INITIALIZATION_OPERATION", tc.operation)
			t.Setenv("STORAGE_INITIALIZATION_TABLE_UUID", "12345678-1234-4234-8234-123456789abc")
			t.Setenv("STORAGE_INITIALIZATION_SCHEMA_SHA256", store.StorageInitializationSchemaSHA256)
			t.Setenv("STORAGE_MAINTENANCE_PATH", tc.gate)
			err := run()
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "PG_DSN") {
				t.Fatal(err)
			}
		})
	}
}
