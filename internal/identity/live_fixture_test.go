package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A private operator-created fixture descriptor, never a production credential.
type identityFixtureTarget struct {
	ContainerID string `json:"container_id"`
	ImageID     string `json:"image_id"`
	RunID       string `json:"run_id"`
	Port        uint16 `json:"port"`
	Secret      string `json:"secret"`
}

func readIdentityFixture(path string) (identityFixtureTarget, error) {
	var target identityFixtureTarget
	bad := errors.New("private identity fixture target is invalid")
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
		!regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(target.RunID) ||
		target.Port == 0 || target.Port == 18089 || len(target.Secret) < 32 || len(target.Secret) > 256 {
		return identityFixtureTarget{}, bad
	}
	return target, nil
}

func pinnedIdentityFixture(t *testing.T, path string) Config {
	t.Helper()
	target, err := readIdentityFixture(path)
	if err != nil {
		t.Fatal("protected identity fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	format := `{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}},"ports":{{json .NetworkSettings.Ports}}}`
	raw, err := exec.CommandContext(ctx, "docker", "inspect", "--format", format, target.ContainerID).Output()
	if err != nil {
		t.Fatal("identity fixture inspection unavailable within its deadline")
	}
	var observed struct {
		ID, Image string
		Running   bool
		Labels    map[string]string
		Ports     map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &observed) != nil ||
		observed.ID != target.ContainerID || observed.Image != target.ImageID || !observed.Running ||
		observed.Labels["captainslog.fixture"] != "identity-disposable" ||
		observed.Labels["captainslog.fixture.run"] != target.RunID ||
		len(observed.Ports["8080/tcp"]) != 1 || observed.Ports["8080/tcp"][0].HostIP != "127.0.0.1" ||
		observed.Ports["8080/tcp"][0].HostPort != strconv.Itoa(int(target.Port)) {
		t.Fatal("identity fixture differs from its protected target")
	}
	url := "http://127.0.0.1:" + strconv.Itoa(int(target.Port))
	return Config{BaseURL: url, PublicBaseURL: url, Realm: "nebulalog",
		ClientID: "nebulalog-identity-manager", ClientSecret: target.Secret, AllowHTTP: true, EnableWrites: true}
}

func TestIdentityFixtureAdmission(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "target.json")
	target := identityFixtureTarget{strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64), strings.Repeat("c", 32), 58003, strings.Repeat("d", 43)}
	write := func(value identityFixtureTarget) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("fixture write failed")
		}
	}
	write(target)
	if got, err := readIdentityFixture(path); err != nil || got != target {
		t.Fatal("private target refused")
	}
	for name, mutate := range map[string]func(*identityFixtureTarget){
		"live port":      func(v *identityFixtureTarget) { v.Port = 18089 },
		"missing port":   func(v *identityFixtureTarget) { v.Port = 0 },
		"container name": func(v *identityFixtureTarget) { v.ContainerID = "keycloak" },
		"mutable image":  func(v *identityFixtureTarget) { v.ImageID = "keycloak:latest" },
		"missing owner":  func(v *identityFixtureTarget) { v.RunID = "" },
		"short secret":   func(v *identityFixtureTarget) { v.Secret = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			other := target
			mutate(&other)
			write(other)
			if _, err := readIdentityFixture(path); err == nil {
				t.Fatal("unsafe fixture accepted")
			}
		})
	}
	write(target)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentityFixture(path); err == nil {
		t.Fatal("readable credential accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "relative.json", link} {
		if _, err := readIdentityFixture(invalid); err == nil {
			t.Fatal("invalid fixture path accepted")
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 8193)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentityFixture(path); err == nil {
		t.Fatal("oversized fixture accepted")
	}
}
