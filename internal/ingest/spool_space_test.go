package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func headroomMessage() message {
	return message{ID: "preserved-headroom-event", Raw: []byte("original raw event"), Sender: "192.0.2.1", IngestedAt: time.Unix(1700000000, 0).UTC()}
}

func TestSpoolSpaceCounterValidation(t *testing.T) {
	for _, tc := range []struct {
		blocks, available uint64
		size              int64
	}{
		{100, 90, -4096}, {100, 90, 0}, {100, 90, 1<<30 + 1},
		{0, 0, 4096}, {100, 101, 4096}, {100, math.MaxUint64, 4096},
		{math.MaxUint64, 1, 4096},
	} {
		if _, err := spoolSpaceFromBlocks(tc.blocks, tc.available, tc.size); err == nil {
			t.Fatalf("invalid counters accepted: %+v", tc)
		}
	}
	got, err := spoolSpaceFromBlocks(100, 7, 4096)
	if err != nil || got.available != 7*4096 || got.blockSize != 4096 {
		t.Fatalf("unprivileged available blocks changed: %+v %v", got, err)
	}
	if got, err = spoolSpaceFromBlocks(100, 0, 4096); err != nil || got.available != 0 {
		t.Fatal("zero available space must be measurable pressure", got, err)
	}
}

func TestSpoolHeadroomBoundaryPreservesExactWAL(t *testing.T) {
	s, err := openSpool(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	m := headroomMessage()
	b, _ := json.Marshal(m)
	allocation := ((uint64(len(b)) + 8 + 4095) / 4096) * 4096
	required := SpoolFilesystemReserveBytes + spoolMetadataHeadroom + allocation
	available := required - 1
	s.space = func(*os.File) (spoolSpace, error) { return spoolSpace{available, 4096}, nil }
	before, _ := os.ReadFile(s.path(1))
	if err = s.append(m); !errors.Is(err, ErrSpoolHeadroom) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.path(1))
	if !reflect.DeepEqual(before, after) || s.pending != 0 || s.bytes != 0 || s.closed {
		t.Fatal("pressure refusal changed or poisoned WAL")
	}
	available++
	if err = s.append(m); err != nil {
		t.Fatal(err)
	}
	items, err := s.peek(2)
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0].Message, m) {
		t.Fatal("recovery changed the admitted record", items, err)
	}
	available = 0
	if err = s.acknowledge(items); err != nil {
		t.Fatal("existing WAL must drain under pressure", err)
	}
}

func TestSpoolSpaceErrorRefusesWithoutLosingOrPoisoningRecords(t *testing.T) {
	s, err := openSpool(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err = s.append(headroomMessage()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.path(1))
	s.space = func(*os.File) (spoolSpace, error) { return spoolSpace{}, errors.New("stat failed") }
	if err = s.append(headroomMessage()); !errors.Is(err, ErrSpoolSpaceUnknown) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.path(1))
	if !reflect.DeepEqual(before, after) || s.pending != 1 || s.closed {
		t.Fatal("unknown capacity mutated WAL")
	}
	s.space = spoolFilesystemSpace
	if err = s.append(headroomMessage()); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolCapArithmeticCannotWrapPastLimit(t *testing.T) {
	s, err := openSpool(t.TempDir(), math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.bytes = math.MaxInt64 - 1
	if err = s.append(headroomMessage()); !errors.Is(err, ErrSpoolFull) {
		t.Fatal(err)
	}
	info, err := s.active.Stat()
	if err != nil || info.Size() != 0 || s.pending != 0 {
		t.Fatal("overflow bypassed WAL limit", info, err)
	}
}

func TestConcurrentSpoolAppendsReobserveHeadroomUnderLock(t *testing.T) {
	s, err := openSpool(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.space = func(*os.File) (spoolSpace, error) {
		if s.bytes == 0 {
			return spoolSpace{1 << 30, 4096}, nil
		}
		return spoolSpace{0, 4096}, nil
	}
	var wg sync.WaitGroup
	var accepted, refused atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.append(headroomMessage())
			if err == nil {
				accepted.Add(1)
			} else if errors.Is(err, ErrSpoolHeadroom) {
				refused.Add(1)
			} else {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || refused.Load() != 15 || s.pending != 1 {
		t.Fatal(accepted.Load(), refused.Load(), s.pending)
	}
}

func TestCollectorPressureBackpressureAndObservedUDPDrop(t *testing.T) {
	cfg := config(t)
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.TCPAddr = "127.0.0.1:0"
	sink := &memorySink{}
	c, err := New(cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var available atomic.Uint64
	c.spool.space = func(*os.File) (spoolSpace, error) { return spoolSpace{available.Load(), 4096}, nil }
	if err = c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	udp, err := net.Dial("udp", address(c, "udp"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	for i := 0; i < 3; i++ {
		if _, err = udp.Write([]byte("pressure datagram")); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() bool { return c.Snapshot().MessagesDropped == 3 })
	if c.Snapshot().QueueDepth != 0 || sink.count() != 0 || !strings.Contains(c.Snapshot().LastError, "filesystem reserve") {
		t.Fatal(c.Snapshot())
	}
	tcp, err := net.Dial("tcp", address(c, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if _, err = tcp.Write([]byte("held TCP event\n")); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Snapshot().MessagesReceived == 4 })
	time.Sleep(150 * time.Millisecond)
	if c.Snapshot().QueueDepth != 0 || sink.count() != 0 || c.Snapshot().MessagesDropped != 3 {
		t.Fatal("pressure admitted or lost the waiting TCP record", c.Snapshot())
	}
	available.Store(1 << 30)
	eventually(t, func() bool { return sink.count() == 1 && c.Snapshot().QueueDepth == 0 })
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.events[0].Raw != "held TCP event" || sink.events[0].ID == "" || c.Snapshot().MessagesDropped != 3 {
		t.Fatal("TCP recovery changed payload or counted a drop")
	}
}

func TestUnknownSpoolCapacityWaitsAndExistingRecordsDrain(t *testing.T) {
	cfg := config(t)
	sink := &memorySink{}
	c, err := New(cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.spool.append(headroomMessage()); err != nil {
		t.Fatal(err)
	}
	c.spool.space = func(*os.File) (spoolSpace, error) { return spoolSpace{}, errors.New("stat temporarily unavailable") }
	if err = c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err = c.Submit(ctx, []byte("not admitted"), "192.0.2.1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	eventually(t, func() bool { return sink.count() == 1 && c.Snapshot().QueueDepth == 0 })
	if !strings.Contains(c.Snapshot().LastError, "space cannot be verified") || c.fatalErr != nil {
		t.Fatal(c.Snapshot())
	}
}
