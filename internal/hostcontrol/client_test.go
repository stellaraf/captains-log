package hostcontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testActor = Actor{strings.Repeat("a", 64), strings.Repeat("b", 64)}

const testPool = "01539441-6e56-4d09-9a02-0acf0ae8e9ec"
const testPlanID = "a9a6644a-6a8d-4dc1-b8de-49e7a915353e"

var testNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func encoded(value any) []byte { b, _ := json.Marshal(value); return b }
func success(data any) []byte {
	return encoded(map[string]any{"schema": 1, "status": "ok", "data": data})
}
func capabilitiesFixture() map[string]any {
	return map[string]any{"control": "read_only", "execution_available": false, "pool_id": testPool, "operations": []any{map[string]any{"operation": "storage.grow", "planning_available": true, "execution_available": false, "reason": "execution_not_qualified"}}}
}
func planFixture() Plan {
	p := Plan{ID: testPlanID, InstallationID: "9c8fbab3-c92b-438a-aa3f-3939e1900e1c", Operation: "storage.grow", Parameters: Parameters{testPool}, ResourceRevision: strings.Repeat("c", 64), IssuedAt: testNow.Unix(), ExpiresAt: testNow.Add(300 * time.Second).Unix(), Review: Review{CurrentBytes: 1024, PresentedBytes: 4096, UnallocatedDiskBytes: 2048, Stages: []string{"partition", "luks", "pv", "lv", "xfs"}, RequiresUnlockCredential: true, Irreversible: true}}
	p.Digest = hash(map[string]any{"id": p.ID, "installation_id": p.InstallationID, "actor": testActor.wire(), "operation": p.Operation, "parameters": p.Parameters, "resource_revision": p.ResourceRevision, "issued_at": p.IssuedAt, "expires_at": p.ExpiresAt})
	return p
}

// Real Unix framing in isolated scratch storage; only this test seam bypasses
// production's Linux connected-peer/ownership check. No TCP server is involved.
func fixtureClient(t *testing.T, reply func(net.Conn, map[string]any)) (*Client, <-chan map[string]any) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nl-host-plan-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "socket")
	listener, err := net.Listen("unix", path)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	done := make(chan struct{})
	requests := make(chan map[string]any, 1)
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var header [4]byte
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 || n > maxRequest {
			return
		}
		body := make([]byte, n)
		if _, err = io.ReadFull(conn, body); err != nil {
			return
		}
		var extra [1]byte
		if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
			return
		}
		var request map[string]any
		if !uniqueJSON(body) || json.Unmarshal(body, &request) != nil {
			return
		}
		requests <- request
		reply(conn, request)
	}()
	t.Cleanup(func() { listener.Close(); <-done; os.RemoveAll(dir) })
	return &Client{dial: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", path) }, clock: func() time.Time { return testNow }, slots: make(chan struct{}, 4)}, requests
}
func framed(conn net.Conn, raw []byte) {
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))
	copy(frame[4:], raw)
	_, _ = conn.Write(frame)
}

func TestCapabilitiesUsesExactPrivateFramedRequest(t *testing.T) {
	client, requests := fixtureClient(t, func(conn net.Conn, _ map[string]any) {
		raw := success(capabilitiesFixture())
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
		for _, b := range append(header[:], raw...) {
			_, _ = conn.Write([]byte{b})
		}
	})
	value, err := client.Capabilities(context.Background(), testActor)
	if err != nil || value.ExecutionAvailable || value.PoolID != testPool {
		t.Fatal(value, err)
	}
	req := <-requests
	if len(req) != 3 || req["schema"] != float64(1) || req["action"] != "capabilities" || hash(req["actor"]) != hash(testActor.wire()) {
		t.Fatal("wire request differs")
	}
	if _, err := json.Marshal(testActor); err == nil {
		t.Fatal("actor exposed as ordinary JSON")
	}
	if strings.Contains(testActor.String(), testActor.subject) {
		t.Fatal("actor leaked")
	}
}

func TestHostRepliesCannotEnableExecutionOrInventMissingFields(t *testing.T) {
	cases := map[string]func(map[string]any){
		"execution":      func(v map[string]any) { v["execution_available"] = true },
		"missing":        func(v map[string]any) { delete(v, "execution_available") },
		"null":           func(v map[string]any) { v["execution_available"] = nil },
		"extra":          func(v map[string]any) { v["private_path"] = "/private" },
		"wrong_control":  func(v map[string]any) { v["control"] = "enabled" },
		"bad_pool":       func(v map[string]any) { v["pool_id"] = "/dev/vda" },
		"no_operations":  func(v map[string]any) { v["operations"] = []any{} },
		"nested_missing": func(v map[string]any) { delete(v["operations"].([]any)[0].(map[string]any), "execution_available") },
		"nested_true":    func(v map[string]any) { v["operations"].([]any)[0].(map[string]any)["execution_available"] = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v := capabilitiesFixture()
			change(v)
			client, _ := fixtureClient(t, func(c net.Conn, _ map[string]any) { framed(c, success(v)) })
			if _, err := client.Capabilities(context.Background(), testActor); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}

func TestProtocolRejectsAmbiguousTruncatedAndExtraFrames(t *testing.T) {
	valid := success(capabilitiesFixture())
	cases := map[string]func(net.Conn){
		"duplicate": func(c net.Conn) {
			framed(c, bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1))
		},
		"escaped_duplicate": func(c net.Conn) {
			framed(c, bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":1,"\u0073chema":1`), 1))
		},
		"utf8": func(c net.Conn) { framed(c, append(valid, 255)) },
		"truncated": func(c net.Conn) {
			var h [4]byte
			binary.BigEndian.PutUint32(h[:], uint32(len(valid)+1))
			c.Write(h[:])
			c.Write(valid)
		},
		"oversized":      func(c net.Conn) { var h [4]byte; binary.BigEndian.PutUint32(h[:], maxResponse+1); c.Write(h[:]) },
		"trailing_frame": func(c net.Conn) { framed(c, valid); framed(c, valid) },
		"zero":           func(c net.Conn) { c.Write(make([]byte, 4)) },
		"reason_injection": func(c net.Conn) {
			framed(c, encoded(map[string]any{"schema": 1, "status": "unavailable", "reason": "private token /etc/secret"}))
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			client, _ := fixtureClient(t, func(c net.Conn, _ map[string]any) { write(c) })
			if _, err := client.Capabilities(context.Background(), testActor); err == nil {
				t.Fatal("bad protocol accepted")
			}
		})
	}
}

func TestCreateAndLookupBindActorPoolPlanAndCurrentTime(t *testing.T) {
	p := planFixture()
	for _, lookup := range []bool{false, true} {
		t.Run(map[bool]string{true: "lookup", false: "create"}[lookup], func(t *testing.T) {
			client, requests := fixtureClient(t, func(c net.Conn, _ map[string]any) { framed(c, success(p)) })
			var got Plan
			var err error
			if lookup {
				got, err = client.LookupPlan(context.Background(), testActor, p.ID, p.Digest)
			} else {
				got, err = client.CreatePlan(context.Background(), testActor, testPool)
			}
			if err != nil || got.Digest != p.Digest {
				t.Fatal(got, err)
			}
			req := <-requests
			if lookup && (req["action"] != "plan.lookup" || req["plan_id"] != p.ID || req["plan_digest"] != p.Digest) {
				t.Fatal("lookup binding lost")
			}
			if !lookup && (req["action"] != "plan.create" || req["operation"] != "storage.grow") {
				t.Fatal("create operation lost")
			}
		})
	}
	cases := map[string]func(*Plan){
		"digest": func(p *Plan) { p.Digest = strings.Repeat("f", 64) },
		"actor": func(p *Plan) {
			p.Digest = hash(map[string]any{"actor": Actor{strings.Repeat("e", 64), testActor.session}.wire()})
		},
		"pool":          func(p *Plan) { p.Parameters.PoolID = p.InstallationID },
		"expired":       func(p *Plan) { p.ExpiresAt = testNow.Unix() },
		"future":        func(p *Plan) { p.IssuedAt = testNow.Add(time.Minute).Unix() },
		"too_long":      func(p *Plan) { p.ExpiresAt = testNow.Add(time.Hour).Unix() },
		"execution":     func(p *Plan) { p.ExecutionAvailable = true },
		"stage_order":   func(p *Plan) { p.Review.Stages = []string{"xfs", "partition"} },
		"stage_repeat":  func(p *Plan) { p.Review.Stages = []string{"lv", "lv"} },
		"stage_unknown": func(p *Plan) { p.Review.Stages = []string{"run_shell"} },
		"credential":    func(p *Plan) { p.Review.RequiresUnlockCredential = false },
		"unsafe_size":   func(p *Plan) { p.Review.CurrentBytes = -1 },
		"null_stages":   func(p *Plan) { p.Review.Stages = nil },
		"reversible":    func(p *Plan) { p.Review.Irreversible = false },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := planFixture()
			change(&bad)
			client, _ := fixtureClient(t, func(c net.Conn, _ map[string]any) { framed(c, success(bad)) })
			if _, err := client.CreatePlan(context.Background(), testActor, testPool); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	t.Run("expires_at_return", func(t *testing.T) {
		client, _ := fixtureClient(t, func(c net.Conn, _ map[string]any) { framed(c, success(p)) })
		client.clock = func() time.Time { return testNow.Add(300 * time.Second) }
		if _, err := client.CreatePlan(context.Background(), testActor, testPool); err == nil {
			t.Fatal("late reply accepted")
		}
	})
}

func TestHostFailureCancellationAndAdmissionStayBounded(t *testing.T) {
	client, _ := fixtureClient(t, func(c net.Conn, _ map[string]any) {
		framed(c, encoded(map[string]any{"schema": 1, "status": "unavailable", "reason": "resource_changed"}))
	})
	_, err := client.LookupPlan(context.Background(), testActor, testPlanID, strings.Repeat("c", 64))
	var refused *Refusal
	if !errors.As(err, &refused) || refused.Code != "resource_changed" || strings.Contains(err.Error(), "resource_changed") {
		t.Fatal("fixed refusal contract changed", err)
	}
	client = &Client{dial: func(context.Context) (net.Conn, error) { t.Fatal("unexpected dial"); return nil, nil }, clock: time.Now, slots: make(chan struct{}, 1)}
	client.slots <- struct{}{}
	if _, err := client.Capabilities(context.Background(), testActor); !errors.As(err, &refused) || refused.Code != "manager_busy" {
		t.Fatal("admission not bounded")
	}
	<-client.slots
	if _, err := client.Capabilities(context.Background(), Actor{}); err == nil {
		t.Fatal("zero identity accepted")
	}
	if _, err := client.CreatePlan(context.Background(), testActor, "/dev/vda"); err == nil {
		t.Fatal("request path accepted")
	}
	cancelled, requests := fixtureClient(t, func(c net.Conn, _ map[string]any) {
		var b [1]byte
		_, _ = c.Read(b[:])
		time.Sleep(100 * time.Millisecond)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-requests; cancel() }()
	started := time.Now()
	if _, err := cancelled.Capabilities(ctx, testActor); err == nil || time.Since(started) > time.Second {
		t.Fatal("cancelled request did not close promptly")
	}
}
