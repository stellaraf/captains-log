package ingest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellaraf/captains-log/internal/panos"
)

type memorySink struct {
	mu       sync.Mutex
	events   []panos.Event
	attempts [][]panos.Event
	fail     bool
}

func (s *memorySink) Insert(ctx context.Context, events []panos.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, append([]panos.Event(nil), events...))
	if s.fail {
		return errors.New("database unavailable")
	}
	s.events = append(s.events, events...)
	return nil
}
func (s *memorySink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.events) }
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func config(t *testing.T) Config {
	return Config{SpoolDir: t.TempDir(), MaxSpoolBytes: 1 << 20, BatchSize: 10, FlushInterval: 10 * time.Millisecond, Logger: quiet()}
}
func sample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../panos/testdata/traffic.log")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func start(t *testing.T, cfg Config, sink Sink) *Collector {
	t.Helper()
	c, err := New(cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(context.Background()); err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func address(c *Collector, kind string) string {
	for _, l := range c.Snapshot().Listeners {
		if l.Transport == kind {
			return l.Address
		}
	}
	return ""
}

func TestFramingCoalescedFragmentedAndUnicode(t *testing.T) {
	payload := "<14>unicode-☁"
	wire := fmt.Sprintf("%d %s%d %s", len([]byte(payload)), payload, 5, "hello")
	r := bufio.NewReaderSize(strings.NewReader(wire), 2)
	for _, want := range []string{payload, "hello"} {
		got, err := ReadFrame(r, 1024)
		if err != nil || string(got) != want {
			t.Fatalf("%q %v", got, err)
		}
	}
	if _, err := ReadFrame(r, 1024); err != io.EOF {
		t.Fatal(err)
	}
	for _, wire := range []string{"<14>line\n<14>next\r\n", "1,CSV,raw\n1,CSV,next\n"} {
		r = bufio.NewReader(strings.NewReader(wire))
		for i := 0; i < 2; i++ {
			if _, err := ReadFrame(r, 1024); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestFramingFailureEvidenceAndBounds(t *testing.T) {
	for _, tc := range []struct {
		wire  string
		max   int
		large bool
	}{{"20 partial", 1024, false}, {"<14>partial", 1024, false}, {"9999999999 ", 128, true}, {"<14>1234567890\n", 8, true}} {
		raw, err := ReadFrame(bufio.NewReader(strings.NewReader(tc.wire)), tc.max)
		if err == nil || len(raw) == 0 {
			t.Fatalf("missing failure evidence %q %v", raw, err)
		}
		if tc.large && !errors.Is(err, ErrFrameTooLarge) {
			t.Fatal(err)
		}
	}
}
func TestUDPAndTCPDeliverRealMessages(t *testing.T) {
	cfg := config(t)
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.TCPAddr = "127.0.0.1:0"
	sink := &memorySink{}
	c := start(t, cfg, sink)
	raw := sample(t)
	udp, err := net.Dial("udp", address(c, "udp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = udp.Write(raw); err != nil {
		t.Fatal(err)
	}
	udp.Close()
	tcp, err := net.Dial("tcp", address(c, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	wire := fmt.Sprintf("%d %s%s\n", len(raw), raw, raw)
	for _, part := range []string{wire[:7], wire[7:33], wire[33:]} {
		if _, err = io.WriteString(tcp, part); err != nil {
			t.Fatal(err)
		}
	}
	tcp.Close()
	eventually(t, func() bool { return sink.count() == 3 && c.Snapshot().QueueDepth == 0 })
	stats := c.Snapshot()
	if stats.MessagesReceived != 3 || stats.MessagesParsed != 3 || stats.EventsInserted != 3 || stats.MessagesDropped != 0 {
		t.Fatalf("%+v", stats)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, e := range sink.events {
		if e.Raw != string(raw) || e.DstIP != "2001:db8::53" || e.SenderIP != "127.0.0.1" {
			t.Fatal(e)
		}
	}
}
func TestIncompleteTCPRecordRetainedAsDiagnostic(t *testing.T) {
	cfg := config(t)
	cfg.TCPAddr = "127.0.0.1:0"
	sink := &memorySink{}
	c := start(t, cfg, sink)
	conn, err := net.Dial("tcp", address(c, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "30 partial CSV")
	conn.Close()
	eventually(t, func() bool { return sink.count() == 1 })
	sink.mu.Lock()
	defer sink.mu.Unlock()
	e := sink.events[0]
	if e.Raw != "partial CSV" || e.ParseStatus != "failed" || !strings.Contains(e.ParseError, "framing") {
		t.Fatal(e)
	}
}
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
func TestTLSListenerAuthenticatedServerAndFraming(t *testing.T) {
	cert, roots := testCertificate(t)
	cfg := config(t)
	cfg.TLSAddr = "127.0.0.1:0"
	cfg.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	sink := &memorySink{}
	c := start(t, cfg, sink)
	conn, err := tls.Dial("tcp", address(c, "tls"), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	raw := sample(t)
	if _, err = fmt.Fprintf(conn, "%d %s", len(raw), raw); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	eventually(t, func() bool { return sink.count() == 1 })
	if _, err = tls.Dial("tcp", address(c, "tls"), &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
func TestOutageRestartReplaysStableIDsAndRawFailures(t *testing.T) {
	cfg := config(t)
	sink := &memorySink{fail: true}
	c, err := New(cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{sample(t), []byte("malformed but important")} {
		if err = c.Submit(context.Background(), raw, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return len(sink.attempts) > 0 })
	if c.Snapshot().QueueDepth != 2 || c.Snapshot().EventsInserted != 0 || c.Snapshot().LastError == "" {
		t.Fatal(c.Snapshot())
	}
	sink.mu.Lock()
	first := sink.attempts[0]
	sink.mu.Unlock()
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	recovered := &memorySink{}
	c2 := start(t, cfg, recovered)
	eventually(t, func() bool { return recovered.count() == 2 && c2.Snapshot().QueueDepth == 0 })
	recovered.mu.Lock()
	defer recovered.mu.Unlock()
	for i, e := range recovered.events {
		if e.ID != first[i].ID || e.Raw != first[i].Raw {
			t.Fatal("replay identity changed")
		}
	}
	if recovered.events[1].ParseStatus != "failed" {
		t.Fatal("malformed event not retained")
	}
}
func TestSpoolBoundBackpressureAndSingleOwner(t *testing.T) {
	cfg := config(t)
	cfg.MaxSpoolBytes = 512
	c, err := New(cfg, &memorySink{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if other, err := New(cfg, &memorySink{}); err == nil {
		other.Close()
		t.Fatal("two collectors share spool")
	}
	if err = c.Submit(context.Background(), []byte(strings.Repeat("x", 150)), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = c.Submit(ctx, []byte(strings.Repeat("x", 150)), "192.0.2.1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if c.Snapshot().QueueDepth != 1 || c.Snapshot().SpoolBytes > 512 {
		t.Fatal(c.Snapshot())
	}
}
func TestSpoolAcknowledgmentReclamationAndCorruption(t *testing.T) {
	dir := t.TempDir()
	s, err := openSpool(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for cycle := 0; cycle < 10; cycle++ {
		m := message{ID: fmt.Sprint(cycle), Raw: []byte(strings.Repeat("x", 200)), Sender: "192.0.2.1", IngestedAt: time.Now()}
		if err = s.append(m); err != nil {
			t.Fatal(err)
		}
		items, err := s.peek(10)
		if err != nil || len(items) != 1 {
			t.Fatalf("%d %v", len(items), err)
		}
		if err = s.acknowledge(items); err != nil {
			t.Fatal(err)
		}
	}
	if count, size := s.stats(); count != 0 || size > 1024 {
		t.Fatalf("%d %d", count, size)
	}
	s.close()
	s, err = openSpool(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if count, _ := s.stats(); count != 0 {
		t.Fatal("acked entries replayed")
	}
	path := s.path(s.segments[len(s.segments)-1])
	s.close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("torn"))
	f.Close()
	if s, err = openSpool(dir, 1024); err == nil {
		s.close()
		t.Fatal("corrupt spool silently accepted")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("corrupt evidence removed")
	}
}
func TestAcknowledgmentPartialRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err = s.append(message{ID: id, Raw: []byte(id), IngestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.peek(2)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.acknowledge(items); err != nil {
		t.Fatal(err)
	}
	s.close()
	s, err = openSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	items, err = s.peek(10)
	if err != nil || len(items) != 1 || items[0].Message.ID != "c" {
		t.Fatalf("%+v %v", items, err)
	}
}
func TestStartFailureRollsBackBoundSockets(t *testing.T) {
	cfg := config(t)
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.TCPAddr = "invalid address"
	c, err := New(cfg, &memorySink{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(context.Background()); err == nil {
		t.Fatal("invalid listener accepted")
	}
	if len(c.Snapshot().Listeners) != 0 {
		t.Fatal("partial listeners survived failed startup")
	}
}
func TestSpoolRestrictivePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	for path, mode := range map[string]os.FileMode{dir: 0700, s.path(1): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s permissions %v", path, info.Mode().Perm())
		}
	}
}

func TestRecentRatesExpireAndIgnoreProcessUptime(t *testing.T) {
	var r rateCounter
	now := time.Unix(100, 0)
	r.observe(now.Add(-6*time.Second), 9999)
	for i := 0; i < 5; i++ {
		r.observe(now.Add(-time.Duration(i)*time.Second), 100)
	}
	eps, bps := r.snapshot(now.Add(rateBucketDuration))
	if eps != 1 || bps != 100 {
		t.Fatalf("got %f events/s %f bytes/s", eps, bps)
	}
	eps, bps = r.snapshot(now.Add(5*time.Second + rateBucketDuration))
	if eps != 0 || bps != 0 {
		t.Fatal("idle buckets did not expire")
	}
	r.observe(now.Add(time.Hour), 250)
	eps, bps = r.snapshot(now.Add(time.Hour + rateBucketDuration))
	if eps != 0.2 || bps != 50 {
		t.Fatal("old uptime diluted new traffic")
	}
}

func TestRecordLargerThanCapacityDoesNotWaitForever(t *testing.T) {
	cfg := config(t)
	cfg.MaxSpoolBytes = 128
	c, err := New(cfg, &memorySink{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = c.Submit(ctx, []byte(strings.Repeat("x", 150)), "192.0.2.1")
	if !errors.Is(err, ErrSpoolRecordTooLarge) {
		t.Fatalf("got %v", err)
	}
	if c.Snapshot().QueueDepth != 0 {
		t.Fatal("oversize record queued")
	}
}

// Simulate an ACK write failure after the sink accepted the batch. The unacked
// record must survive restart with the same identity; listeners must fail closed.
func TestACKFailureStopsListenersAndPreservesReplay(t *testing.T) {
	cfg := config(t)
	cfg.TCPAddr = "127.0.0.1:0"
	sink := &memorySink{}
	c := start(t, cfg, sink)
	if err := os.Mkdir(filepath.Join(cfg.SpoolDir, "ack.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.Submit(context.Background(), []byte("replay me"), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Snapshot().Listeners[0].Status == "failed" })
	if sink.count() != 1 || c.Snapshot().QueueDepth != 1 {
		t.Fatal("ACK failure discarded pending data")
	}
	if err := c.Submit(context.Background(), []byte("must not admit"), "192.0.2.1"); err == nil {
		t.Fatal("accepted with dead delivery worker")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.SpoolDir, "ack.tmp")); err != nil {
		t.Fatal(err)
	}
	recovered := &memorySink{}
	c2 := start(t, cfg, recovered)
	eventually(t, func() bool { return recovered.count() == 1 && c2.Snapshot().QueueDepth == 0 })
	sink.mu.Lock()
	defer sink.mu.Unlock()
	recovered.mu.Lock()
	defer recovered.mu.Unlock()
	if recovered.events[0].ID != sink.events[0].ID {
		t.Fatal("ambiguous commit replay changed identity")
	}
}

func TestSteadyRollingRateDoesNotDipAtSecondBoundaries(t *testing.T) {
	var r rateCounter
	start := time.Unix(100, 0)
	// 100 EPS uniformly spaced; every complete five-second window must be 100.
	for i := 0; i < 600; i++ {
		at := start.Add(time.Duration(i) * 10 * time.Millisecond)
		r.observe(at, 100)
		if i >= 500 {
			eps, bps := r.snapshot(at)
			if eps != 100 || bps != 10000 {
				t.Fatalf("at %v: %f %f", at, eps, bps)
			}
		}
	}
}

func TestMissingWALSegmentIsNotSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	s, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			if err := s.rotate(); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.append(message{ID: fmt.Sprint(i), Raw: []byte("evidence"), IngestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path(2)); err != nil {
		t.Fatal(err)
	}
	if recovered, err := openSpool(dir, 1<<20); err == nil {
		recovered.close()
		t.Fatal("missing unacknowledged segment silently skipped")
	}
	if _, err := os.Stat(s.path(3)); err != nil {
		t.Fatal("remaining evidence was changed")
	}
}
