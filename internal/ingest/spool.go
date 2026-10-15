package ingest

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrSpoolFull = errors.New("durable spool is full")
var ErrSpoolRecordTooLarge = errors.New("message cannot fit in configured durable spool capacity")
var ErrClosed = errors.New("collector closed")

const maxRecordSize = 4 << 20
const segmentSize = 16 << 20

type message struct {
	ID           string    `json:"id"`
	Raw          []byte    `json:"raw"`
	Sender       string    `json:"sender"`
	IngestedAt   time.Time `json:"ingested_at"`
	FramingError string    `json:"framing_error,omitempty"`
}
type position struct {
	Segment uint64 `json:"segment"`
	Offset  int64  `json:"offset"`
}
type queued struct {
	Message message
	End     position
}
type spool struct {
	mu         sync.Mutex
	dir        string
	limit      int64
	segments   []uint64
	ack        position
	active     *os.File
	lock       *os.File
	activeSize int64
	bytes      int64
	pending    uint64
	closed     bool
	space      func(*os.File) (spoolSpace, error)
}

func openSpool(dir string, limit int64) (*spool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("spool is already owned by another process: %w", err)
	}
	s := &spool{dir: dir, limit: limit, lock: lock, space: spoolFilesystemSpace}
	cleanup := func(err error) (*spool, error) {
		if s.active != nil {
			s.active.Close()
		}
		lock.Close()
		return nil, err
	}
	if b, e := os.ReadFile(filepath.Join(dir, "ack.json")); e == nil {
		if e = json.Unmarshal(b, &s.ack); e != nil {
			return cleanup(fmt.Errorf("invalid spool acknowledgment: %w", e))
		}
	} else if !os.IsNotExist(e) {
		return cleanup(e)
	}
	paths, e := filepath.Glob(filepath.Join(dir, "*.wal"))
	if e != nil {
		return cleanup(e)
	}
	for _, path := range paths {
		n, e := strconv.ParseUint(strings.TrimSuffix(filepath.Base(path), ".wal"), 10, 64)
		if e != nil {
			return cleanup(fmt.Errorf("invalid spool filename %s", path))
		}
		s.segments = append(s.segments, n)
	}
	sort.Slice(s.segments, func(i, j int) bool { return s.segments[i] < s.segments[j] })
	if s.ack.Offset < 0 || (s.ack.Segment == 0 && s.ack.Offset != 0) {
		return cleanup(errors.New("invalid spool acknowledgment position"))
	}
	for i, n := range s.segments {
		if n == 0 || (i > 0 && n != s.segments[i-1]+1) {
			return cleanup(errors.New("spool segment sequence has missing data"))
		}
	}
	if len(s.segments) > 0 {
		first := s.segments[0]
		if (s.ack.Segment == 0 && first != 1) || (first > s.ack.Segment && first-s.ack.Segment > 1) {
			return cleanup(errors.New("spool checkpoint or segment is missing"))
		}
	}
	if len(s.segments) == 0 {
		if s.ack.Segment > 0 {
			return cleanup(errors.New("spool acknowledgment references missing data"))
		}
		if err = s.rotate(); err != nil {
			return cleanup(err)
		}
	} else {
		last := s.segments[len(s.segments)-1]
		s.active, err = os.OpenFile(s.path(last), os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			return cleanup(err)
		}
		info, e := s.active.Stat()
		if e != nil {
			return cleanup(e)
		}
		s.activeSize = info.Size()
	}
	// Scan lengths/checksums before listening. Corruption fails visibly, never skips data.
	for _, segment := range s.segments {
		f, e := os.Open(s.path(segment))
		if e != nil {
			return cleanup(e)
		}
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return cleanup(e)
		}
		s.bytes += info.Size()
		offset := int64(0)
		boundary := s.ack.Offset == 0
		for {
			_, size, e := readRecord(f)
			if e == io.EOF {
				break
			}
			if e != nil {
				f.Close()
				return cleanup(fmt.Errorf("spool segment %d offset %d is corrupt: %w", segment, offset, e))
			}
			offset += size
			if segment == s.ack.Segment && offset == s.ack.Offset {
				boundary = true
			}
			if segment > s.ack.Segment || (segment == s.ack.Segment && offset > s.ack.Offset) {
				s.pending++
			}
		}
		f.Close()
		if segment == s.ack.Segment && (!boundary || s.ack.Offset > info.Size()) {
			return cleanup(errors.New("spool acknowledgment is not a record boundary"))
		}
	}
	if len(s.segments) > 0 && s.ack.Segment > s.segments[len(s.segments)-1] {
		return cleanup(errors.New("spool acknowledgment exceeds data"))
	}
	return s, nil
}
func (s *spool) path(n uint64) string { return filepath.Join(s.dir, fmt.Sprintf("%020d.wal", n)) }
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *spool) rotate() error {
	n := uint64(1)
	if len(s.segments) > 0 {
		n = s.segments[len(s.segments)-1] + 1
	}
	f, err := os.OpenFile(s.path(n), os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if err = syncDir(s.dir); err != nil {
		f.Close()
		return err
	}
	if s.active != nil {
		if err = s.active.Close(); err != nil {
			f.Close()
			return err
		}
	}
	s.active = f
	s.activeSize = 0
	s.segments = append(s.segments, n)
	return nil
}
func (s *spool) append(m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxRecordSize {
		return errors.New("message exceeds spool record limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	record := make([]byte, 8+len(b))
	binary.BigEndian.PutUint32(record[:4], uint32(len(b)))
	binary.BigEndian.PutUint32(record[4:8], crc32.ChecksumIEEE(b))
	copy(record[8:], b)
	if int64(len(record)) > s.limit {
		return ErrSpoolRecordTooLarge
	}
	if s.bytes < 0 || s.bytes > s.limit || int64(len(record)) > s.limit-s.bytes {
		return ErrSpoolFull
	}
	if err = s.checkHeadroom(uint64(len(record))); err != nil {
		return err
	}
	if s.activeSize >= segmentSize {
		if err = s.rotate(); err != nil {
			return err
		}
		// Inspect the new open file too, rather than assuming its path still
		// resolves to the filesystem observed before rotation.
		if err = s.checkHeadroom(uint64(len(record))); err != nil {
			return err
		}
	}
	// A failed write/sync poisons this instance. Restart performs explicit integrity
	// checks; continuing could otherwise hide a torn record in the middle of a WAL.
	n, err := s.active.Write(record)
	s.bytes += int64(n)
	s.activeSize += int64(n)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.active.Sync()
	}
	if err != nil {
		s.closed = true
		return fmt.Errorf("durable spool append failed: %w", err)
	}
	s.pending++
	return nil
}
func readRecord(r io.Reader) (message, int64, error) {
	var m message
	header := make([]byte, 8)
	n, err := io.ReadFull(r, header)
	if err != nil {
		if n == 0 && err == io.EOF {
			return m, 0, io.EOF
		}
		return m, int64(n), err
	}
	length := binary.BigEndian.Uint32(header[:4])
	if length == 0 || length > maxRecordSize {
		return m, 8, errors.New("invalid record size")
	}
	b := make([]byte, length)
	n, err = io.ReadFull(r, b)
	if err != nil {
		return m, int64(n + 8), err
	}
	if crc32.ChecksumIEEE(b) != binary.BigEndian.Uint32(header[4:]) {
		return m, int64(n + 8), errors.New("record checksum mismatch")
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, int64(n + 8), err
	}
	return m, int64(n + 8), nil
}
func (s *spool) peek(count int) ([]queued, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	out := make([]queued, 0, count)
	for _, segment := range s.segments {
		if segment < s.ack.Segment {
			continue
		}
		offset := int64(0)
		if segment == s.ack.Segment {
			offset = s.ack.Offset
		}
		f, err := os.Open(s.path(segment))
		if err != nil {
			return nil, err
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		for len(out) < count {
			m, n, err := readRecord(f)
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return nil, err
			}
			offset += n
			out = append(out, queued{Message: m, End: position{segment, offset}})
		}
		f.Close()
		if len(out) == count {
			break
		}
	}
	return out, nil
}
func (s *spool) acknowledge(items []queued) error {
	if len(items) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	end := items[len(items)-1].End
	b, _ := json.Marshal(end)
	tmp := filepath.Join(s.dir, "ack.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(s.dir, "ack.json")); err != nil {
		return err
	}
	if err = syncDir(s.dir); err != nil {
		return err
	}
	s.ack = end
	if s.pending < uint64(len(items)) {
		return errors.New("spool pending count underflow")
	}
	s.pending -= uint64(len(items))
	// Keep a small active tail; when entirely drained, rotate so all acknowledged
	// bytes can be reclaimed even with a small configured capacity.
	threshold := int64(segmentSize)
	if s.limit/4 < threshold {
		threshold = s.limit / 4
	}
	if s.pending == 0 && s.activeSize >= threshold {
		if err = s.rotate(); err != nil {
			return err
		}
	}
	kept := s.segments[:0]
	for _, n := range s.segments {
		removable := n < s.ack.Segment || (n == s.ack.Segment && s.pending == 0 && n != s.segments[len(s.segments)-1])
		if removable {
			info, e := os.Stat(s.path(n))
			if e != nil {
				return e
			}
			if e = os.Remove(s.path(n)); e != nil {
				return e
			}
			s.bytes -= info.Size()
		} else {
			kept = append(kept, n)
		}
	}
	s.segments = kept
	return syncDir(s.dir)
}
func (s *spool) stats() (uint64, int64) { s.mu.Lock(); defer s.mu.Unlock(); return s.pending, s.bytes }
func (s *spool) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	err := s.active.Close()
	lockErr := s.lock.Close()
	if err != nil {
		return err
	}
	return lockErr
}
