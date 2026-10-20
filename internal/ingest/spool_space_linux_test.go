package ingest

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// Run only in a disposable container with an empty 320MiB tmpfs mounted here.
// Refuse ordinary disks and larger mounts before creating the bounded filler.
func TestSpoolHeadroomConstrainedFilesystem(t *testing.T) {
	if os.Getenv("NEBULALOG_TEST_SPOOL_TMPFS") != "1" {
		t.Skip("requires an isolated bounded tmpfs")
	}
	const mount = "/spool-headroom"
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mount, &stat); err != nil {
		t.Fatal(err)
	}
	space, err := spoolSpaceFromBlocks(stat.Blocks, stat.Bavail, stat.Frsize)
	if err != nil || stat.Type != 0x01021994 || stat.Blocks*uint64(stat.Frsize) < 300<<20 || stat.Blocks*uint64(stat.Frsize) > 384<<20 {
		t.Fatal("refusing an unqualified test filesystem", err)
	}
	entries, err := os.ReadDir(mount)
	if err != nil || len(entries) != 0 {
		t.Fatal("test mount must be empty", err)
	}
	dir, err := os.MkdirTemp(mount, "spool-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s, err := openSpool(dir, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if s != nil {
			s.close()
		}
	}()
	m := headroomMessage()
	if err = s.append(m); err != nil {
		t.Fatal(err)
	}
	space, err = spoolFilesystemSpace(s.active)
	if err != nil {
		t.Fatal(err)
	}
	filler, err := os.Create(filepath.Join(dir, "bounded-pressure.fixture"))
	if err != nil {
		t.Fatal(err)
	}
	target := SpoolFilesystemReserveBytes + spoolMetadataHeadroom - space.blockSize
	if space.available <= target || space.available-target > 128<<20 {
		filler.Close()
		t.Fatal("unqualified fill bound")
	}
	zero, err := os.Open("/dev/zero")
	if err != nil {
		filler.Close()
		t.Fatal(err)
	}
	_, err = io.CopyN(filler, zero, int64(space.available-target))
	zero.Close()
	if err == nil {
		err = filler.Sync()
	}
	filler.Close()
	if err != nil {
		t.Fatal(err)
	}
	pressured, err := spoolFilesystemSpace(s.active)
	if err != nil || pressured.available < SpoolFilesystemReserveBytes {
		t.Fatal("test consumed reserved space", pressured, err)
	}
	if err = s.append(m); !errors.Is(err, ErrSpoolHeadroom) {
		t.Fatal("actual pressure did not refuse append", err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	s = nil
	s, err = openSpool(dir, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.peek(2)
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0].Message, m) {
		t.Fatal("restart changed retained evidence", items, err)
	}
	if err = s.append(m); !errors.Is(err, ErrSpoolHeadroom) {
		t.Fatal("restart bypassed pressure", err)
	}
	if err = s.acknowledge(items); err != nil {
		t.Fatal("checkpoint could not drain below admission threshold", err)
	}
	if err = os.Remove(filepath.Join(dir, "bounded-pressure.fixture")); err != nil {
		t.Fatal(err)
	}
	if err = s.append(m); err != nil {
		t.Fatal("space recovery did not resume admission", err)
	}
	items, err = s.peek(2)
	if err != nil || len(items) != 1 || !reflect.DeepEqual(items[0].Message, m) {
		t.Fatal("recovery changed record", items, err)
	}
	t.Logf("actual tmpfs pressure refused at %d available bytes, preserving %d-byte reserve and exact WAL across restart", pressured.available, SpoolFilesystemReserveBytes)
}
