package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectorStatusRejectsStaleOrUnsafeObservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	now := time.Now()
	stats := Stats{MessagesReceived: 31, EventsInserted: 29, QueueDepth: 2,
		Listeners: []ListenerStatus{{Transport: "tcp", Address: ":514", Status: "listening"}}}
	if err := WriteStatus(path, stats, now); err != nil {
		t.Fatal(err)
	}
	observed, err := ReadStatus(path, now.Add(time.Second))
	if err != nil || observed.EventsInserted != 29 || len(observed.Listeners) != 1 {
		t.Fatal(observed, err)
	}
	if _, err = ReadStatus(path, now.Add(StatusMaxAge+time.Second)); err == nil {
		t.Fatal("accepted dead collector")
	}
	if _, err = ReadStatus(path, now.Add(-time.Minute)); err == nil {
		t.Fatal("accepted future observation")
	}
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadStatus(path, now); err == nil {
		t.Fatal("accepted externally writable observation")
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadStatus(link, now); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestCollectorStatusAtomicUpdatesAndMalformedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	now := time.Now()
	for n := uint64(0); n < 20; n++ {
		if err := WriteStatus(path, Stats{EventsInserted: n}, now); err != nil {
			t.Fatal(err)
		}
		got, err := ReadStatus(path, now)
		if err != nil || got.EventsInserted != n {
			t.Fatal(got, err)
		}
	}
	for _, value := range []string{"{", `{"schema":1}`, `{"schema":2}`, `{} {}`} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStatus(path, now); err == nil {
			t.Fatal("accepted invalid observation", value)
		}
	}
}
