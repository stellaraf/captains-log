// Package ingest provides native syslog listeners and a durable at-least-once spool.
package ingest

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stellaraf/captains-log/internal/panos"
)

type Sink interface {
	Insert(context.Context, []panos.Event) error
}
type Config struct {
	UDPAddr         string
	TCPAddr         string
	TLSAddr         string
	TLSConfig       *tls.Config
	SpoolDir        string
	MaxSpoolBytes   int64
	BatchSize       int
	FlushInterval   time.Duration
	Parser          *panos.Parser
	MaxMessageBytes int
	MaxConnections  int
	ReadTimeout     time.Duration
	Logger          *slog.Logger
}
type ListenerStatus struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Status    string `json:"status"`
}
type Stats struct {
	MessagesReceived       uint64           `json:"messages_received"`
	MessagesParsed         uint64           `json:"messages_parsed"`
	ParseFailures          uint64           `json:"parse_failures"`
	EventsInserted         uint64           `json:"events_inserted"`
	QueueDepth             uint64           `json:"queue_depth"`
	SpoolBytes             int64            `json:"spool_bytes"`
	MessagesDropped        uint64           `json:"messages_dropped"`
	EventsPerSecond        float64          `json:"events_per_second"`
	BytesPerSecond         float64          `json:"bytes_per_second"`
	AverageEventsPerSecond float64          `json:"average_events_per_second"`
	AverageBytesPerSecond  float64          `json:"average_bytes_per_second"`
	RateWindowSeconds      int              `json:"rate_window_seconds"`
	LastEventReceived      *time.Time       `json:"last_event_received"`
	Listeners              []ListenerStatus `json:"listeners"`
	LastError              string           `json:"last_error"`
}
type Collector struct {
	config                                             Config
	sink                                               Sink
	spool                                              *spool
	received, parsed, failed, inserted, dropped, bytes atomic.Uint64
	lastReceived                                       atomic.Int64
	rates                                              rateCounter
	mu                                                 sync.Mutex
	listeners                                          []ListenerStatus
	closers                                            []io.Closer
	connections                                        map[net.Conn]bool
	lastError                                          string
	started                                            bool
	closed                                             bool
	cancel                                             context.CancelFunc
	startTime                                          time.Time
	wake                                               chan struct{}
	wg                                                 sync.WaitGroup
	closeOnce                                          sync.Once
	closeErr                                           error
	failure                                            chan struct{}
	fatalErr                                           error
}

func New(config Config, sink Sink) (*Collector, error) {
	if sink == nil {
		return nil, errors.New("ingest sink is required")
	}
	if config.SpoolDir == "" {
		return nil, errors.New("spool directory is required")
	}
	if config.MaxSpoolBytes <= 0 {
		config.MaxSpoolBytes = 1 << 30
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 1000
	}
	if config.BatchSize > 10000 {
		return nil, errors.New("batch size cannot exceed 10000")
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = time.Second
	}
	if config.Parser == nil {
		config.Parser = panos.NewParser(panos.Options{})
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxMessageBytes <= 0 {
		config.MaxMessageBytes = 1 << 20
	}
	if config.MaxMessageBytes > 2<<20 {
		return nil, errors.New("maximum message size cannot exceed 2 MiB")
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 128
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 2 * time.Minute
	}
	if config.TLSAddr != "" {
		if config.TLSConfig == nil || len(config.TLSConfig.Certificates) == 0 && config.TLSConfig.GetCertificate == nil {
			return nil, errors.New("TLS listener requires a server certificate")
		}
		config.TLSConfig = config.TLSConfig.Clone()
		if config.TLSConfig.MinVersion < tls.VersionTLS12 {
			config.TLSConfig.MinVersion = tls.VersionTLS12
		}
	}
	s, err := openSpool(config.SpoolDir, config.MaxSpoolBytes)
	if err != nil {
		return nil, err
	}
	return &Collector{config: config, sink: sink, spool: s, startTime: time.Now(), wake: make(chan struct{}, 1), failure: make(chan struct{}), connections: map[net.Conn]bool{}}, nil
}
func (c *Collector) recordError(err error) {
	c.mu.Lock()
	c.lastError = err.Error()
	c.mu.Unlock()
	c.config.Logger.Error("syslog ingest", "error", err)
}

// fail stops admission after a terminal WAL error. The spool is retained for
// restart/investigation; a dead delivery worker must never leave healthy listeners.
func (c *Collector) fail(err error) {
	c.mu.Lock()
	if c.fatalErr == nil {
		c.fatalErr = err
		c.lastError = err.Error()
		for i := range c.listeners {
			c.listeners[i].Status = "failed"
		}
		close(c.failure)
		if c.cancel != nil {
			c.cancel()
		}
	}
	c.mu.Unlock()
	c.config.Logger.Error("syslog collector stopped", "error", err)
}

func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if c.fatalErr != nil {
		return c.fatalErr
	}
	if c.started {
		return errors.New("collector already started")
	}
	var starts []func(context.Context)
	rollback := func(err error) error {
		for _, closer := range c.closers {
			closer.Close()
		}
		c.closers = nil
		c.listeners = nil
		return err
	}
	if c.config.UDPAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", c.config.UDPAddr)
		if err != nil {
			return rollback(err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return rollback(err)
		}
		if err = conn.SetReadBuffer(4 << 20); err != nil {
			c.config.Logger.Warn("cannot increase UDP receive buffer", "error", err)
		}
		c.closers = append(c.closers, conn)
		c.listeners = append(c.listeners, ListenerStatus{"udp", conn.LocalAddr().String(), "listening"})
		starts = append(starts, func(ctx context.Context) { c.udp(ctx, conn) })
	}
	for _, spec := range []struct{ addr, kind string }{{c.config.TCPAddr, "tcp"}, {c.config.TLSAddr, "tls"}} {
		if spec.addr == "" {
			continue
		}
		listener, err := net.Listen("tcp", spec.addr)
		if err != nil {
			return rollback(err)
		}
		if spec.kind == "tls" {
			listener = tls.NewListener(listener, c.config.TLSConfig)
		}
		c.closers = append(c.closers, listener)
		c.listeners = append(c.listeners, ListenerStatus{spec.kind, listener.Addr().String(), "listening"})
		starts = append(starts, func(ctx context.Context) { c.accept(ctx, listener) })
	}
	runctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true
	for _, start := range starts {
		c.wg.Add(1)
		go func(f func(context.Context)) { defer c.wg.Done(); f(runctx) }(start)
	}
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.deliver(runctx) }()
	// Cancellation closes sockets so blocking Accept/Read calls cannot hold shutdown.
	go func() {
		<-runctx.Done()
		c.mu.Lock()
		for _, closer := range c.closers {
			closer.Close()
		}
		for conn := range c.connections {
			conn.Close()
		}
		c.mu.Unlock()
	}()
	return nil
}
func (c *Collector) Run(ctx context.Context) error {
	if err := c.Start(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-c.failure:
	}
	err := c.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	return errors.Join(c.fatalErr, err)
}
func (c *Collector) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.cancel != nil {
			c.cancel()
		}
		for _, closer := range c.closers {
			closer.Close()
		}
		for conn := range c.connections {
			conn.Close()
		}
		for i := range c.listeners {
			if c.fatalErr == nil {
				c.listeners[i].Status = "stopped"
			}
		}
		c.mu.Unlock()
		c.wg.Wait()
		c.closeErr = c.spool.close()
	})
	return c.closeErr
}
func (c *Collector) message(raw []byte, sender, framingError string) message {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("system random generator unavailable")
	}
	now := time.Now().UTC()
	c.received.Add(1)
	c.bytes.Add(uint64(len(raw)))
	c.lastReceived.Store(now.UnixNano())
	c.rates.observe(now, uint64(len(raw)))
	return message{ID: hex.EncodeToString(id[:]), Raw: append([]byte(nil), raw...), Sender: sender, IngestedAt: now, FramingError: framingError}
}
func (c *Collector) enqueue(ctx context.Context, m message, wait bool) error {
	warnedFull := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.spool.append(m)
		if err == nil {
			select {
			case c.wake <- struct{}{}:
			default:
			}
			return nil
		}
		if !errors.Is(err, ErrSpoolFull) || !wait {
			if !errors.Is(err, ErrSpoolFull) && !errors.Is(err, ErrSpoolRecordTooLarge) && !errors.Is(err, ErrClosed) {
				c.fail(err)
			} else {
				c.recordError(err)
			}
			return err
		}
		if !warnedFull {
			c.recordError(ErrSpoolFull)
			warnedFull = true
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Submit waits for durable spool capacity, providing backpressure to callers.
func (c *Collector) Submit(ctx context.Context, raw []byte, sender string) error {
	c.mu.Lock()
	closed, fatal := c.closed, c.fatalErr
	c.mu.Unlock()
	if fatal != nil {
		return fatal
	}
	if closed {
		return ErrClosed
	}
	if len(raw) > c.config.MaxMessageBytes {
		c.dropped.Add(1)
		err := ErrFrameTooLarge
		c.recordError(err)
		return err
	}
	return c.enqueue(ctx, c.message(raw, sender, ""), true)
}
func (c *Collector) udp(ctx context.Context, conn *net.UDPConn) {
	// UDP payloads cannot exceed 65535 bytes; a full-size buffer avoids truncation.
	buf := make([]byte, 65535)
	for {
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil {
				c.recordError(err)
			}
			return
		}
		m := c.message(buf[:n], sender.IP.String(), "")
		if n > c.config.MaxMessageBytes {
			m.FramingError = "UDP datagram exceeds configured message size"
		}
		if err = c.enqueue(ctx, m, false); err != nil {
			c.dropped.Add(1)
		}
	}
}
func (c *Collector) accept(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				c.recordError(err)
			}
			return
		}
		c.mu.Lock()
		if len(c.connections) >= c.config.MaxConnections || c.closed {
			c.mu.Unlock()
			conn.Close()
			c.dropped.Add(1)
			c.recordError(errors.New("syslog connection limit reached"))
			continue
		}
		c.connections[conn] = true
		c.wg.Add(1)
		c.mu.Unlock()
		go func() {
			defer c.wg.Done()
			defer conn.Close()
			defer func() { c.mu.Lock(); delete(c.connections, conn); c.mu.Unlock() }()
			r := bufio.NewReader(conn)
			for {
				conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))
				raw, err := ReadFrame(r, c.config.MaxMessageBytes)
				if err != nil {
					if len(raw) > 0 {
						m := c.message(raw, conn.RemoteAddr().String(), err.Error())
						if e := c.enqueue(ctx, m, true); e != nil {
							c.dropped.Add(1)
						}
					}
					if err != io.EOF && ctx.Err() == nil {
						c.recordError(err)
					}
					if errors.Is(err, ErrFrameTooLarge) {
						c.dropped.Add(1)
					}
					return
				}
				if e := c.Submit(ctx, raw, conn.RemoteAddr().String()); e != nil {
					c.dropped.Add(1)
					return
				}
			}
		}()
	}
}
func (c *Collector) deliver(ctx context.Context) {
	ticker := time.NewTicker(c.config.FlushInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		items, err := c.spool.peek(c.config.BatchSize)
		if err != nil {
			c.fail(fmt.Errorf("durable spool read failed: %w", err))
			return
		}
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-c.wake:
			}
			continue
		}
		// Allow a short interval to accumulate a batch instead of flushing every event.
		if len(items) < c.config.BatchSize {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			items, err = c.spool.peek(c.config.BatchSize)
			if err != nil {
				c.fail(fmt.Errorf("durable spool read failed: %w", err))
				return
			}
		}
		events := make([]panos.Event, len(items))
		for i, item := range items {
			m := item.Message
			e := c.config.Parser.Parse(m.Raw, m.Sender, m.IngestedAt)
			e.ID = m.ID
			if m.FramingError != "" {
				e.ParseStatus = "failed"
				e.ParseError = "syslog framing: " + m.FramingError
			}
			events[i] = e
			if e.ParseStatus == "parsed" {
				c.parsed.Add(1)
			} else {
				c.failed.Add(1)
			}
		}
		backoff := 100 * time.Millisecond
		for {
			if ctx.Err() != nil {
				return
			}
			if err = c.sink.Insert(ctx, events); err == nil {
				break
			}
			c.recordError(fmt.Errorf("database delivery failed, retaining %d events: %w", len(events), err))
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
		}
		if err = c.spool.acknowledge(items); err != nil {
			c.fail(fmt.Errorf("database accepted events but spool acknowledgment failed: %w", err))
			return
		}
		c.inserted.Add(uint64(len(events)))
	}
}
func (c *Collector) Snapshot() Stats {
	count, size := c.spool.stats()
	c.mu.Lock()
	listeners := append([]ListenerStatus{}, c.listeners...)
	lastError := c.lastError
	c.mu.Unlock()
	elapsed := time.Since(c.startTime).Seconds()
	stats := Stats{MessagesReceived: c.received.Load(), MessagesParsed: c.parsed.Load(), ParseFailures: c.failed.Load(), EventsInserted: c.inserted.Load(), QueueDepth: count, SpoolBytes: size, MessagesDropped: c.dropped.Load(), Listeners: listeners, LastError: lastError}
	if elapsed > 0 {
		stats.AverageEventsPerSecond = float64(stats.MessagesReceived) / elapsed
		stats.AverageBytesPerSecond = float64(c.bytes.Load()) / elapsed
	}
	stats.EventsPerSecond, stats.BytesPerSecond = c.rates.snapshot(time.Now())
	stats.RateWindowSeconds = rateWindowSeconds
	if n := c.lastReceived.Load(); n != 0 {
		t := time.Unix(0, n).UTC()
		stats.LastEventReceived = &t
	}
	return stats
}
