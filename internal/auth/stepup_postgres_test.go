package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is an operator-owned fixture description, never a browser input or a
// production DSN. It pins an already-running test service and contains a private
// fixture credential. Do not include its contents in test output or receipts.
type stepUpPGFixtureTarget struct {
	ContainerID string `json:"container_id"`
	ImageID     string `json:"image_id"`
	DataPath    string `json:"data_path"`
	VolumeName  string `json:"volume_name,omitempty"`
	Port        uint16 `json:"port"`
	Password    string `json:"password"`
	SystemID    string `json:"system_id"`
}

func readStepUpPGFixtureTarget(path string) (stepUpPGFixtureTarget, error) {
	var target stepUpPGFixtureTarget
	bad := errors.New("private PostgreSQL fixture target is invalid")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return target, bad
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return target, bad
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return target, bad
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > 8192 {
		return target, bad
	}
	f, err := os.Open(path)
	if err != nil {
		return target, bad
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return target, bad
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || len(raw) > 8192 || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return target, bad
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&target) != nil || decoder.Decode(new(any)) != io.EOF ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(target.ContainerID) ||
		!regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(target.ImageID) ||
		!regexp.MustCompile(`^[0-9]{1,20}$`).MatchString(target.SystemID) ||
		target.Port == 0 || target.Port == 25432 || len(target.Password) == 0 || len(target.Password) > 1024 {
		return stepUpPGFixtureTarget{}, bad
	}
	if target.VolumeName != "" {
		if target.DataPath != "" || !regexp.MustCompile(`^captainslog-stepup-[a-f0-9]{32}$`).MatchString(target.VolumeName) {
			return stepUpPGFixtureTarget{}, bad
		}
		return target, nil
	}
	if !filepath.IsAbs(target.DataPath) {
		return stepUpPGFixtureTarget{}, bad
	}
	resolved, err = filepath.EvalSymlinks(target.DataPath)
	if err != nil || resolved != target.DataPath {
		return stepUpPGFixtureTarget{}, bad
	}
	return target, nil
}

func pinnedStepUpPGFixture(t *testing.T, path string) (*pgxpool.Config, string) {
	t.Helper()
	target, err := readStepUpPGFixtureTarget(path)
	if err != nil {
		t.Fatal("protected PostgreSQL fixture target unavailable")
	}
	// Inspect only nonsecret fields, and never restart, create or pull a service.
	format := `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"label":{{json (index .Config.Labels "captainslog.fixture")}},"memory":{{json .HostConfig.Memory}},"cpu":{{json .HostConfig.NanoCpus}},"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}}}`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "inspect", "--format", format, target.ContainerID).Output()
	var observed struct {
		ID, Image, Label string
		Running          bool
		Memory, CPU      int64
		Mounts           []struct {
			Type, Name, Source, Destination string
			RW                              bool
		}
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
	}
	if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &observed) != nil ||
		observed.ID != target.ContainerID || observed.Image != target.ImageID || !observed.Running ||
		observed.Label != "emergency-destructive" || observed.Memory <= 0 || observed.Memory > 384<<20 || observed.CPU <= 0 || observed.CPU > 1e9 ||
		len(observed.Mounts) != 1 || observed.Mounts[0].Destination != "/var/lib/postgresql/data" || !observed.Mounts[0].RW ||
		len(observed.Ports) != 1 || len(observed.Ports["5432/tcp"]) != 1 || observed.Ports["5432/tcp"][0].HostIP != "127.0.0.1" || observed.Ports["5432/tcp"][0].HostPort != strconv.Itoa(int(target.Port)) {
		t.Fatal("existing PostgreSQL fixture identity differs from its protected target")
	}
	mount := observed.Mounts[0]
	if target.VolumeName == "" {
		if mount.Type != "bind" || mount.Source != target.DataPath {
			t.Fatal("PostgreSQL fixture bind mount differs from its protected target")
		}
	} else {
		// Docker Desktop bind mounts do not reliably preserve database UID
		// ownership. Admit only a uniquely named, explicitly labelled local
		// fixture volume, never an arbitrary existing database volume.
		var volume struct {
			Name, Driver, Scope, Mountpoint string
			Labels, Options                 map[string]string
		}
		raw, err := exec.CommandContext(ctx, "docker", "volume", "inspect", "--format", "{{json .}}", target.VolumeName).Output()
		if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &volume) != nil ||
			mount.Type != "volume" || mount.Name != target.VolumeName ||
			volume.Name != target.VolumeName || volume.Driver != "local" || volume.Scope != "local" ||
			len(volume.Options) != 0 || mount.Source != volume.Mountpoint ||
			volume.Labels["captainslog.fixture"] != "emergency-destructive" ||
			volume.Labels["captainslog.fixture.run"] != strings.TrimPrefix(target.VolumeName, "captainslog-stepup-") {
			t.Fatal("PostgreSQL fixture volume differs from its protected target")
		}
	}
	config, err := pgxpool.ParseConfig("postgres://127.0.0.1:" + strconv.Itoa(int(target.Port)) + "/emergency_test?sslmode=disable")
	if err != nil {
		t.Fatal("isolated PostgreSQL fixture configuration invalid")
	}
	config.ConnConfig.User, config.ConnConfig.Password = "emergency_test", target.Password
	config.ConnConfig.RuntimeParams = map[string]string{"application_name": "captainslog-stepup-fixture", "statement_timeout": "5000", "lock_timeout": "1000", "idle_in_transaction_session_timeout": "10000", "temp_file_limit": "16384", "work_mem": "1MB"}
	return config, target.SystemID
}

func TestPostgresStepUpFixtureTargetAdmission(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal("fixture directory unavailable")
	}
	path := filepath.Join(root, "target.json")
	target := stepUpPGFixtureTarget{ContainerID: strings.Repeat("a", 64), ImageID: "sha256:" + strings.Repeat("b", 64), DataPath: root, Port: 58002, Password: "synthetic-fixture-only", SystemID: "1"}
	write := func(value stepUpPGFixtureTarget, mode os.FileMode) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if os.WriteFile(path, raw, 0600) != nil || os.Chmod(path, mode) != nil {
			t.Fatal("fixture target write failed")
		}
	}
	write(target, 0600)
	if got, err := readStepUpPGFixtureTarget(path); err != nil || got != target {
		t.Fatal("private exact fixture target refused")
	}
	volumeTarget := target
	volumeTarget.DataPath = ""
	volumeTarget.VolumeName = "captainslog-stepup-" + strings.Repeat("c", 32)
	write(volumeTarget, 0600)
	if got, err := readStepUpPGFixtureTarget(path); err != nil || got != volumeTarget {
		t.Fatal("private exact volume fixture target refused")
	}
	for name, mutate := range map[string]func(*stepUpPGFixtureTarget){
		"live dev port":           func(v *stepUpPGFixtureTarget) { v.Port = 25432 },
		"missing credential":      func(v *stepUpPGFixtureTarget) { v.Password = "" },
		"container name":          func(v *stepUpPGFixtureTarget) { v.ContainerID = "postgres" },
		"mutable image":           func(v *stepUpPGFixtureTarget) { v.ImageID = "postgres:latest" },
		"relative mount":          func(v *stepUpPGFixtureTarget) { v.DataPath = "data" },
		"ambiguous mount":         func(v *stepUpPGFixtureTarget) { v.VolumeName = volumeTarget.VolumeName },
		"unowned volume":          func(v *stepUpPGFixtureTarget) { v.DataPath = ""; v.VolumeName = "production-postgres" },
		"missing server identity": func(v *stepUpPGFixtureTarget) { v.SystemID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			other := target
			mutate(&other)
			write(other, 0600)
			if _, err := readStepUpPGFixtureTarget(path); err == nil {
				t.Fatal("unsafe fixture target accepted")
			}
		})
	}
	write(target, 0644)
	if _, err := readStepUpPGFixtureTarget(path); err == nil {
		t.Fatal("readable credential accepted")
	}
	write(target, 0600)
	link := filepath.Join(root, "link.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture symlink unavailable")
	}
	if _, err := readStepUpPGFixtureTarget(link); err == nil {
		t.Fatal("symlink target accepted")
	}
	if os.WriteFile(path, []byte(strings.Repeat("x", 8193)), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if _, err := readStepUpPGFixtureTarget(path); err == nil {
		t.Fatal("oversized fixture target accepted")
	}
}

func TestPostgresStepUpFixtureSelectorNeverFallsBack(t *testing.T) {
	if os.Getenv("NEBULALOG_STEPUP_FIXTURE_REFUSAL_CHILD") == "1" {
		postgresStepUpTestPool(t)
		t.Fatal("invalid selected fixture reached a database")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestPostgresStepUpFixtureSelectorNeverFallsBack$")
	cmd.Env = append(os.Environ(), "NEBULALOG_STEPUP_FIXTURE_REFUSAL_CHILD=1", "NEBULALOG_STEPUP_POSTGRES_TEST=1", "NEBULALOG_STEPUP_POSTGRES_FIXTURE_CONFIG=")
	raw, err := cmd.CombinedOutput()
	if err == nil || ctx.Err() != nil || !strings.Contains(string(raw), "protected PostgreSQL fixture target unavailable") || strings.Contains(string(raw), "local PostgreSQL configuration") {
		t.Fatal("invalid fixture selector did not refuse before legacy fallback")
	}
}

func postgresStepUpFixture() stepUpPending {
	now := time.Now().UTC().Truncate(time.Second)
	p := stepUpPending{
		StateHash: strings.Repeat("1", 64), Nonce: strings.Repeat("n", 43), Verifier: strings.Repeat("v", 43), PolicyDigest: strings.Repeat("2", 64),
		Actor:     stepUpActor{Issuer: "https://issuer.example/realms/nebulalog", Subject: "synthetic-subject", ClientID: "nebulalog", SessionDigest: strings.Repeat("3", 64)},
		Binding:   StepUpBinding{InstallationID: "11111111-2222-3333-4444-555555555555", Operation: "storage.grow", PlanID: "66666666-7777-8888-9999-aaaaaaaaaaaa", PlanDigest: strings.Repeat("4", 64), ResourceRevision: strings.Repeat("5", 64), ExpiresAt: now.Add(2 * time.Minute)},
		CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	p.Binding.Challenge = syntheticStepUpChallenge(p.Binding, p.Actor.Issuer, p.Actor.ClientID, p.Actor.Subject, "synthetic-original-session", now)
	p.Nonce = p.Binding.Challenge.Nonce
	p.Actor.SessionDigest = p.Binding.Challenge.SessionDigest
	return p
}

func TestPostgresStepUpRefusesInvalidPendingBeforeDatabaseAccess(t *testing.T) {
	mutations := map[string]func(*stepUpPending){
		"raw state":        func(p *stepUpPending) { p.StateHash = strings.Repeat("s", 43) },
		"uppercase digest": func(p *stepUpPending) { p.PolicyDigest = strings.Repeat("A", 64) },
		"short nonce":      func(p *stepUpPending) { p.Nonce = "short" },
		"invalid verifier": func(p *stepUpPending) { p.Verifier = strings.Repeat("!", 43) },
		"empty actor":      func(p *stepUpPending) { p.Actor.Subject = "" },
		"control actor":    func(p *stepUpPending) { p.Actor.ClientID = "client\n" },
		"oversize issuer":  func(p *stepUpPending) { p.Actor.Issuer = strings.Repeat("i", 2049) },
		"raw session":      func(p *stepUpPending) { p.Actor.SessionDigest = "raw-session-id" },
		"installation":     func(p *stepUpPending) { p.Binding.InstallationID = "../installation" },
		"operation":        func(p *stepUpPending) { p.Binding.Operation = "storage.grow\n" },
		"plan ID":          func(p *stepUpPending) { p.Binding.PlanID = "plan" },
		"plan digest":      func(p *stepUpPending) { p.Binding.PlanDigest = "plan" },
		"revision":         func(p *stepUpPending) { p.Binding.ResourceRevision = "revision" },
		"missing creation": func(p *stepUpPending) { p.CreatedAt = time.Time{} },
		"empty lifetime":   func(p *stepUpPending) { p.ExpiresAt = p.CreatedAt },
		"long lifetime": func(p *stepUpPending) {
			p.ExpiresAt = p.CreatedAt.Add(121 * time.Second)
			p.Binding.ExpiresAt = p.ExpiresAt
		},
		"expired binding":                  func(p *stepUpPending) { p.Binding.ExpiresAt = p.ExpiresAt.Add(-time.Microsecond) },
		"creation precision":               func(p *stepUpPending) { p.CreatedAt = p.CreatedAt.Add(time.Nanosecond) },
		"expiry precision":                 func(p *stepUpPending) { p.ExpiresAt = p.ExpiresAt.Add(-time.Nanosecond) },
		"binding precision":                func(p *stepUpPending) { p.Binding.ExpiresAt = p.Binding.ExpiresAt.Add(time.Nanosecond) },
		"missing host challenge":           func(p *stepUpPending) { p.Binding.Challenge = HostChallenge{} },
		"local substituted nonce":          func(p *stepUpPending) { p.Nonce = strings.Repeat("x", 43) },
		"challenge subject":                func(p *stepUpPending) { p.Binding.Challenge.SubjectDigest = strings.Repeat("e", 64) },
		"challenge session":                func(p *stepUpPending) { p.Binding.Challenge.SessionDigest = strings.Repeat("e", 64) },
		"challenge installation":           func(p *stepUpPending) { p.Binding.Challenge.InstallationID = "aaaaaaaa-2222-3333-4444-555555555555" },
		"challenge operation":              func(p *stepUpPending) { p.Binding.Challenge.Operation = "backup.create" },
		"challenge plan":                   func(p *stepUpPending) { p.Binding.Challenge.PlanID = "aaaaaaaa-7777-8888-9999-aaaaaaaaaaaa" },
		"challenge digest":                 func(p *stepUpPending) { p.Binding.Challenge.PlanDigest = strings.Repeat("e", 64) },
		"challenge revision":               func(p *stepUpPending) { p.Binding.Challenge.ResourceRevision = strings.Repeat("e", 64) },
		"challenge policy":                 func(p *stepUpPending) { p.Binding.Challenge.PolicyGeneration = "missing" },
		"challenge issued after creation":  func(p *stepUpPending) { p.Binding.Challenge.IssuedAt++ },
		"challenge expires before pending": func(p *stepUpPending) { p.Binding.Challenge.ExpiresAt-- },
	}
	store := NewPostgresStepUpStore(nil)
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := postgresStepUpFixture()
			mutate(&p)
			if err := store.Insert(context.Background(), p); !errors.Is(err, ErrStepUpTransaction) {
				t.Fatal("invalid transaction reached database")
			}
		})
	}
}

func TestPostgresStepUpUnavailableAndRedaction(t *testing.T) {
	p := postgresStepUpFixture()
	for _, store := range []*PostgresStepUpStore{nil, NewPostgresStepUpStore(nil)} {
		if err := store.Insert(context.Background(), p); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("missing PostgreSQL did not fail closed")
		}
		got, err := store.Consume(context.Background(), p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpUnavailable) || got != (stepUpPending{}) {
			t.Fatal("missing PostgreSQL returned evidence")
		}
		got, err = store.Consume(context.Background(), "raw-state", p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
			t.Fatal("raw OAuth state accepted")
		}
		if fmt.Sprintf("%v", store) != "PostgresStepUpStore[redacted]" || fmt.Sprintf("%#v", store) != "PostgresStepUpStore[redacted]" {
			t.Fatal("store formatting is not redacted")
		}
	}
	if _, err := json.Marshal(NewPostgresStepUpStore(nil)); err == nil {
		t.Fatal("store serialized")
	}
}

// Explicit opt-in uses only a randomly named schema in the existing loopback
// development database. It never migrates public, starts a service, or prints
// connection strings/credentials, query arguments, or transaction evidence.
func postgresStepUpTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("NEBULALOG_STEPUP_POSTGRES_TEST") != "1" {
		t.Skip("opt-in isolated local PostgreSQL integration")
	}
	var config *pgxpool.Config
	var expectedSystemID string
	if path, selected := os.LookupEnv("NEBULALOG_STEPUP_POSTGRES_FIXTURE_CONFIG"); selected {
		// A selected but invalid fixture must never fall back to the live dev DB.
		config, expectedSystemID = pinnedStepUpPGFixture(t, path)
	} else {
		b, err := os.ReadFile(filepath.Join("..", "..", ".local", "dev.env"))
		if err != nil {
			t.Fatal("local PostgreSQL configuration unavailable")
		}
		var password string
		for _, line := range strings.Split(string(b), "\n") {
			if key, value, ok := strings.Cut(line, "="); ok && key == "PG_PASSWORD" {
				password = value
			}
		}
		if password == "" {
			t.Fatal("local PostgreSQL credential unavailable")
		}
		config, err = pgxpool.ParseConfig("postgres://127.0.0.1:25432/nebulalog?sslmode=disable")
		if err != nil {
			t.Fatal("local PostgreSQL configuration invalid")
		}
		config.ConnConfig.User, config.ConnConfig.Password = "nebulalog", password
	}
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	config.MaxConns = 4
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("local PostgreSQL connection unavailable")
	}
	if expectedSystemID != "" {
		var systemID, database, user, version string
		err = admin.QueryRow(ctx, "SELECT system_identifier::text,current_database(),current_user,current_setting('server_version_num') FROM pg_control_system()").Scan(&systemID, &database, &user, &version)
		if err != nil || systemID != expectedSystemID || database != "emergency_test" || user != "emergency_test" || version != "170011" {
			admin.Close()
			t.Fatal("connected PostgreSQL server differs from the isolated fixture")
		}
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		admin.Close()
		t.Fatal("test schema entropy unavailable")
	}
	schema := "stepup_test_" + hex.EncodeToString(suffix[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("isolated test schema could not be created")
	}
	t.Cleanup(func() {
		defer admin.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("isolated test schema cleanup failed")
			return
		}
		var remains bool
		if err := admin.QueryRow(cleanupCtx, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)", schema).Scan(&remains); err != nil || remains {
			t.Error("isolated test schema removal could not be verified")
		}
	})
	isolated := config.Copy()
	isolated.ConnConfig.RuntimeParams["search_path"] = quoted
	pool, err := pgxpool.NewWithConfig(ctx, isolated)
	if err != nil {
		t.Fatal("isolated test connection unavailable")
	}
	t.Cleanup(pool.Close)
	for range 2 {
		for _, name := range []string{"host_stepup.sql", "host_stepup_v2.sql"} {
			migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
			if err != nil {
				t.Fatal("explicit step-up migration unavailable")
			}
			if _, err := pool.Exec(ctx, string(migration)); err != nil {
				t.Fatal("explicit step-up migration failed in isolated schema")
			}
		}
	}
	return pool
}

func insertPostgresStepUpFixture(t *testing.T, pool *pgxpool.Pool, p stepUpPending) {
	t.Helper()
	if err := NewPostgresStepUpStore(pool).Insert(context.Background(), p); err != nil {
		t.Fatal("synthetic transaction insert failed")
	}
}

func TestPostgresStepUpAtomicIntegration(t *testing.T) {
	pool := postgresStepUpTestPool(t)
	store := NewPostgresStepUpStore(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clear := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, "TRUNCATE host_stepup_pending_v2"); err != nil {
			t.Fatal("isolated table cleanup failed")
		}
	}

	t.Run("all bindings refuse without consuming", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		p.Binding.Challenge.ExpiresAt--
		p.ExpiresAt = p.ExpiresAt.Add(-time.Second)
		insertPostgresStepUpFixture(t, pool, p)
		mutations := map[string]func(*stepUpPending){
			"state":          func(p *stepUpPending) { p.StateHash = strings.Repeat("a", 64) },
			"issuer":         func(p *stepUpPending) { p.Actor.Issuer += "/other" },
			"subject":        func(p *stepUpPending) { p.Actor.Subject += "-other" },
			"client":         func(p *stepUpPending) { p.Actor.ClientID += "-other" },
			"session":        func(p *stepUpPending) { p.Actor.SessionDigest = strings.Repeat("a", 64) },
			"installation":   func(p *stepUpPending) { p.Binding.InstallationID = "aaaaaaaa-2222-3333-4444-555555555555" },
			"operation":      func(p *stepUpPending) { p.Binding.Operation = "storage.add_disk" },
			"plan":           func(p *stepUpPending) { p.Binding.PlanID = "aaaaaaaa-7777-8888-9999-aaaaaaaaaaaa" },
			"plan digest":    func(p *stepUpPending) { p.Binding.PlanDigest = strings.Repeat("a", 64) },
			"revision":       func(p *stepUpPending) { p.Binding.ResourceRevision = strings.Repeat("a", 64) },
			"binding expiry": func(p *stepUpPending) { p.Binding.ExpiresAt = p.Binding.ExpiresAt.Add(time.Microsecond) },
			"policy":         func(p *stepUpPending) { p.PolicyDigest = strings.Repeat("a", 64) },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				other := p
				mutate(&other)
				got, err := store.Consume(ctx, other.StateHash, other.Actor, other.Binding, other.PolicyDigest, p.CreatedAt)
				if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
					t.Fatal("mismatched binding returned evidence")
				}
			})
		}
		for name, mutate := range stepUpChallengeMutations() {
			t.Run("host challenge "+name, func(t *testing.T) {
				other := p
				mutate(&other.Binding.Challenge)
				got, err := store.Consume(ctx, other.StateHash, other.Actor, other.Binding, other.PolicyDigest, p.CreatedAt)
				if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
					t.Fatal("changed host challenge returned database evidence")
				}
			})
		}
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if err != nil || got != p {
			t.Fatal("matching transaction did not survive mismatches or failed exact round trip")
		}
		got, err = store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
			t.Fatal("replay returned evidence")
		}
	})

	t.Run("legacy rows remain inert without promotion", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		_, err := pool.Exec(ctx, `INSERT INTO host_stepup_pending
 SELECT state_hash, nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at, created_at, expires_at FROM host_stepup_pending_v2`)
		if err != nil {
			t.Fatal("legacy synthetic transaction seed failed")
		}
		clear(t)
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
			t.Fatal("legacy pending row gained host-challenge authority")
		}
		var legacy int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM host_stepup_pending").Scan(&legacy); err != nil || legacy != 1 {
			t.Fatal("legacy authority evidence was not retained separately")
		}
	})

	t.Run("duplicate state does not replace transaction", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		other := p
		other.Nonce = strings.Repeat("o", 43)
		other.Binding.Challenge.Nonce = other.Nonce
		if err := store.Insert(ctx, other); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("duplicate state replaced pending evidence or exposed database details")
		}
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if err != nil || got != p {
			t.Fatal("duplicate state damaged the original transaction")
		}
	})

	t.Run("creation and expiry boundaries", func(t *testing.T) {
		for _, delta := range []time.Duration{-time.Microsecond, 0, 120*time.Second - time.Microsecond, 120 * time.Second} {
			clear(t)
			p := postgresStepUpFixture()
			insertPostgresStepUpFixture(t, pool, p)
			_, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt.Add(delta))
			if delta < 0 || delta >= 120*time.Second {
				if !errors.Is(err, ErrStepUpTransaction) {
					t.Fatal("time boundary did not refuse transaction")
				}
			} else if err != nil {
				t.Fatal("valid exclusive-expiry boundary refused")
			}
		}
	})

	t.Run("concurrent replicas consume exactly once", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		var successes, failures atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 24 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := NewPostgresStepUpStore(pool).Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
				if err == nil && got.Nonce == p.Nonce && got.Verifier == p.Verifier {
					successes.Add(1)
				} else if !errors.Is(err, ErrStepUpTransaction) || got != (stepUpPending{}) {
					failures.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if successes.Load() != 1 || failures.Load() != 0 {
			t.Fatal("concurrent callbacks violated single consumption")
		}
	})

	t.Run("database constraints reject malformed rows", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		for _, assignment := range []string{
			"record_schema = 1", "challenge_schema = 0", "challenge_id = 'invalid'", "challenge_subject_digest = 'invalid'",
			"challenge_operation_schema = 0", "challenge_action = '../run'", "challenge_request_digest = 'invalid'", "challenge_policy_generation = 'invalid'",
			"challenge_issued_at = -1", "challenge_expires_at = challenge_issued_at", "challenge_expires_at = challenge_issued_at + 121",
			"state_hash = 'raw-state'", "nonce = 'short'", "pkce_verifier = 'short'", "policy_digest = 'bad'",
			"actor_subject = ''", "actor_issuer = ''", "actor_client_id = ''", "actor_session_digest = 'raw-session'",
			"installation_id = 'bad'", "operation = '../run'", "plan_id = 'bad'", "plan_digest = 'bad'", "resource_revision = 'bad'",
			"expires_at = created_at", "expires_at = created_at + interval '121 seconds'", "binding_expires_at = created_at",
			"created_at = '-infinity'", "expires_at = 'infinity'", "binding_expires_at = 'infinity'",
		} {
			_, err := pool.Exec(ctx, "UPDATE host_stepup_pending_v2 SET "+assignment)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Fatal("database accepted malformed transaction")
			}
		}
	})

	t.Run("bounded retention preserves pending rows", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		_, err := pool.Exec(ctx, `INSERT INTO host_stepup_pending_v2
 SELECT 2, lpad(to_hex(n),64,'0'), nonce, pkce_verifier, policy_digest,
 actor_issuer, actor_subject, actor_client_id, actor_session_digest,
 installation_id, operation, plan_id, plan_digest, resource_revision,
 binding_expires_at - interval '5 minutes', created_at - interval '5 minutes', expires_at - interval '5 minutes',
 challenge_schema, challenge_id, challenge_subject_digest, challenge_operation_schema,
 challenge_action, challenge_request_digest, challenge_policy_generation, challenge_issued_at - 300, challenge_expires_at - 300
 FROM host_stepup_pending_v2 CROSS JOIN generate_series(1,$1) AS n`, stepUpRetentionBatch+9)
		if err != nil {
			t.Fatal("expired synthetic transaction seed failed")
		}
		p.StateHash = strings.Repeat("e", 64)
		insertPostgresStepUpFixture(t, pool, p)
		var expired, live int
		if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE expires_at <= statement_timestamp()), count(*) FILTER (WHERE expires_at > statement_timestamp()) FROM host_stepup_pending_v2`).Scan(&expired, &live); err != nil || expired != 9 || live != 2 {
			t.Fatal("retention exceeded batch bound or erased pending transaction")
		}
	})

	t.Run("database failure returns no evidence", func(t *testing.T) {
		clear(t)
		p := postgresStepUpFixture()
		insertPostgresStepUpFixture(t, pool, p)
		pool.Close()
		got, err := store.Consume(ctx, p.StateHash, p.Actor, p.Binding, p.PolicyDigest, p.CreatedAt)
		if !errors.Is(err, ErrStepUpUnavailable) || got != (stepUpPending{}) {
			t.Fatal("database failure exposed evidence or a database error")
		}
		if err := store.Insert(ctx, p); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatal("database insert failure exposed a database error")
		}
	})
}
