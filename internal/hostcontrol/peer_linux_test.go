//go:build linux

package hostcontrol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireIsolatedLinux(t *testing.T) {
	t.Helper()
	if os.Getenv("NEBULALOG_HOST_PEER_TEST") != "1" {
		t.Skip("opt in only inside the disposable Linux fixture container")
	}
	var fs syscall.Statfs_t
	if os.Geteuid() != 0 || syscall.Statfs("/run", &fs) != nil || fs.Type != 0x01021994 {
		t.Fatal("fixture requires root and a private tmpfs /run")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("fixture requires disposable Docker container")
	}
	if _, err := os.Lstat("/run/nebulalog-control"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusing existing host control directory")
	}
	t.Cleanup(func() { _ = os.Remove(SocketPath); _ = os.Remove("/run/nebulalog-control") })
}

func waitReady(t *testing.T, reader io.Reader) {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(reader)
		if scanner.Scan() {
			done <- scanner.Text()
		} else {
			done <- ""
		}
	}()
	select {
	case value := <-done:
		if value != "READY" {
			t.Fatal("fixture did not become ready")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture startup deadline")
	}
}

func childCommand(ctx context.Context, mode string, uid uint32) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxPeerChild$", "-test.v")
	cmd.Env = append(os.Environ(), "NEBULALOG_HOST_PLAN_CHILD="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{20002}}}
	return cmd
}

func TestLinuxPythonStoragePlanRoundTrip(t *testing.T) {
	requireIsolatedLinux(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	// Stop the Python service through SIGTERM before canceling CommandContext;
	// cancellation kills it before its private journal cleanup can unwind.
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3.14", "/src/appliance/tests/host_plan_linux_fixture.py")
	cmd.Env = append(os.Environ(), "NEBULALOG_HOST_PLAN_FIXTURE=1", "PYTHONPATH=/src/appliance", "PYTHONDONTWRITEBYTECODE=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Error("fixture shutdown signal failed", err)
		}
		if err := cmd.Wait(); err != nil {
			t.Errorf("fixture did not shut down cleanly: %v: %s", err, stderr.String())
		}
	})
	waitReady(t, stdout)
	// Root owns the service but is not the dedicated API peer. Proving only the
	// server's UID is insufficient; Python must also enforce the caller's UID.
	// Read its peer rejection without sending a request: Linux can reset a
	// socket closed with unread unauthorized request bytes, obscuring the
	// structured refusal while the production client still fails closed.
	conn, err := dialProtected(ctx)
	if err != nil {
		t.Fatal("protected root connection", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	denial, readErr := io.ReadAll(io.LimitReader(conn, maxResponse+5))
	_ = conn.Close()
	if readErr != nil || len(denial) < 4 || len(denial)-4 != int(binary.BigEndian.Uint32(denial[:4])) {
		t.Fatal("missing framed kernel peer refusal")
	}
	fields, err := object(denial[4:], "schema", "status", "reason")
	var schema int
	var status, reason string
	if err != nil || json.Unmarshal(fields["schema"], &schema) != nil || json.Unmarshal(fields["status"], &status) != nil || json.Unmarshal(fields["reason"], &reason) != nil || schema != 1 || status != "unavailable" || reason != "peer_not_authorized" {
		t.Fatal("root was not rejected by the Python kernel peer check")
	}
	_, err = New().Capabilities(ctx, testActor)
	var refused *Refusal
	if !errors.Is(err, ErrUnavailable) && (!errors.As(err, &refused) || refused.Code != "peer_not_authorized") {
		t.Fatal("root caller bypassed API peer restriction", err)
	}
	child := childCommand(ctx, "api-client", 10001)
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("dedicated API peer integration failed: %s", output)
	}
	if !bytes.Contains(output, []byte("PASS")) {
		t.Fatal("client test did not run")
	}
}

func TestLinuxPathOwnershipCannotReplaceConnectedPeerProof(t *testing.T) {
	requireIsolatedLinux(t)
	if err := os.Mkdir("/run/nebulalog-control", 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod("/run/nebulalog-control", 0777); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := childCommand(ctx, "untrusted-server", 10002)
	// Keep the helper's readiness line separate from the Go test runner banners.
	cmd.Args = []string{os.Args[0], "-test.run=^TestLinuxPeerChild$"}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitReady(t, stdout)
	// The named inode and parents now look trusted, but the listening process
	// remains UID10002. A path-only client would disclose its private actor.
	for _, path := range []string{"/run/nebulalog-control", SocketPath} {
		if err := os.Chown(path, 0, 20002); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod("/run/nebulalog-control", 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(SocketPath, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Capabilities(ctx, testActor); err == nil {
		t.Fatal("untrusted connected server was accepted")
	}
	rest, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rest, []byte("NO_REQUEST")) {
		t.Fatal("request may have reached untrusted server")
	}
}

func TestLinuxPeerChild(t *testing.T) {
	switch os.Getenv("NEBULALOG_HOST_PLAN_CHILD") {
	case "api-client":
		if os.Geteuid() != 10001 || os.Getegid() != 10001 {
			t.Fatal("API identity was not dropped")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c := New()
		caps, err := c.Capabilities(ctx, testActor)
		if err != nil {
			t.Fatal("capabilities", err)
		}
		p, err := c.CreatePlan(ctx, testActor, caps.PoolID)
		if err != nil {
			t.Fatal("plan create", err)
		}
		if p.ExecutionAvailable || p.Digest == "" || len(p.Review.Stages) == 0 {
			t.Fatal("invalid real Python review")
		}
		lookup, err := c.LookupPlan(ctx, testActor, p.ID, p.Digest)
		if err != nil || lookup.Digest != p.Digest {
			t.Fatal("plan lookup", err)
		}
		_, err = c.LookupPlan(ctx, Actor{testActor.subject, strings.Repeat("d", 64)}, p.ID, p.Digest)
		var refused *Refusal
		if !errors.As(err, &refused) || refused.Code != "plan_unavailable" {
			t.Fatal("wrong session obtained plan", err)
		}
		_, err = c.call(ctx, testActor, "job.accept", nil)
		if !errors.As(err, &refused) || refused.Code != "invalid_request" {
			t.Fatal("execution action reached planning service")
		}
	case "untrusted-server":
		if os.Geteuid() != 10002 {
			t.Fatal("untrusted server identity was not dropped")
		}
		listener, err := net.Listen("unix", SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		fmt.Println("READY")
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		if n, err := conn.Read(one[:]); n != 0 || err != io.EOF {
			t.Fatal("client disclosed bytes to untrusted connected peer")
		}
		fmt.Println("NO_REQUEST")
	default:
		t.Skip("subprocess fixture only")
	}
}
