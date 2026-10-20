//go:build linux

package store

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEmergencyHostGateNativePermissions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated Linux root fixture to create trusted files and run unprivileged reader")
	}
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	base, e := os.MkdirTemp(cwd, "host-gate-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(base)
	if e = os.Chmod(base, 0755); e != nil {
		t.Fatal(e)
	}
	// Go's build directory can be private to root. Give the unprivileged
	// child its own executable inside this root-owned, traversable fixture.
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	source, e := os.Open(executable)
	if e != nil {
		t.Fatal(e)
	}
	child := filepath.Join(base, "gate-reader.test")
	destination, e := os.OpenFile(child, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if e != nil {
		source.Close()
		t.Fatal(e)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	source.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	check := func(t *testing.T, path, want string) {
		t.Helper()
		cmd := exec.Command(child, "-test.run=^TestEmergencyHostGateUnprivilegedChild$", "-test.v")
		cmd.Env = append(os.Environ(), "CAPTAINSLOG_GATE_TEST_CHILD="+path, "CAPTAINSLOG_GATE_TEST_WANT="+want)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("unprivileged gate result: %v %s", e, out)
		}
	}
	for _, name := range []string{"idle", "hold", "mode", "owner", "link", "directory", "fifo", "oversized", "duplicate", "writable-parent", "missing"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(base, name)
			if e := os.Mkdir(dir, 0755); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "gate.json")
			raw := `{"schema":1,"held":false,"delivery_held":false,"operation":null}`
			want := "refuse"
			if name == "hold" {
				raw = `{"schema":1,"held":true,"delivery_held":true,"operation":"` + strings.Repeat("a", 64) + `"}`
				want = "hold"
			}
			if name == "idle" {
				want = "idle"
			}
			if name == "oversized" {
				raw = strings.Repeat(" ", 4097) + raw
			}
			if name == "duplicate" {
				raw = `{"schema":1,"held":true,"held":false,"delivery_held":false,"operation":null}`
			}
			if e := os.WriteFile(path, []byte(raw), 0644); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "mode":
				os.Chmod(path, 0666)
			case "owner":
				os.Chown(path, 65534, 65534)
			case "link":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "directory":
				os.Remove(path)
				os.Mkdir(path, 0755)
			case "fifo":
				os.Remove(path)
				if e := syscall.Mkfifo(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "writable-parent":
				os.Chmod(dir, 0777)
			case "missing":
				os.Remove(path)
			}
			check(t, path, want)
		})
	}
	// A root app on a writable mount must not claim that ownership bits alone
	// make the gate immutable. Production mounts it read-only and runs nonroot.
	path := filepath.Join(base, "idle", "gate.json")
	if _, e = readHostStorageGate(path); e == nil {
		t.Fatal("writable gate parent accepted for privileged process")
	}
}
