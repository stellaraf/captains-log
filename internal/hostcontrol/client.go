// Package hostcontrol implements only the protected read-only host plan protocol.
// A plan is not a grant. There is no job acceptance, cancellation or execution.
package hostcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/stellaraf/captains-log/internal/auth"
)

const SocketPath = "/run/nebulalog-control/plans.sock"
const maxRequest = 16 << 10
const maxResponse = 64 << 10

var ErrUnavailable = errors.New("host plan service unavailable")
var ErrIdentity = errors.New("verified administrator session required")
var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Actor contains hashes of the original verified application identity. Only
// ActorFromContext can create one outside this package. It is private metadata,
// not independently host-verified human authorization.
type Actor struct{ subject, session string }

func (a Actor) String() string               { return "HostPlanActor[redacted]" }
func (a Actor) GoString() string             { return a.String() }
func (a Actor) MarshalJSON() ([]byte, error) { return nil, ErrIdentity }
func (a Actor) wire() map[string]string {
	return map[string]string{"subject": a.subject, "session_id": a.session}
}
func (a Actor) valid() bool {
	return digestPattern.MatchString(a.subject) && digestPattern.MatchString(a.session)
}

func hash(value any) string {
	b, _ := json.Marshal(value)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func ActorFromContext(ctx context.Context, clientID string, now time.Time) (Actor, error) {
	u := auth.Current(ctx)
	s, ok := auth.CurrentSession(ctx)
	if !ok || u.Role != "ADMINISTRATOR" || !s.MatchesApplication(u.ID, clientID, now) {
		return Actor{}, ErrIdentity
	}
	subject := hash([]string{"nebulalog.host-plan.subject.v1", s.Issuer(), s.ClientID(), s.Subject()})
	return Actor{subject, hash([]string{"nebulalog.host-plan.session.v1", subject, s.SessionID()})}, nil
}

type Operation struct {
	Operation          string `json:"operation"`
	PlanningAvailable  bool   `json:"planning_available"`
	ExecutionAvailable bool   `json:"execution_available"`
	Reason             string `json:"reason"`
}
type Capabilities struct {
	Control            string      `json:"control"`
	ExecutionAvailable bool        `json:"execution_available"`
	PoolID             string      `json:"pool_id"`
	Operations         []Operation `json:"operations"`
}
type Parameters struct {
	PoolID string `json:"pool_id"`
}
type Review struct {
	CurrentBytes             int64    `json:"current_bytes"`
	PresentedBytes           int64    `json:"presented_bytes"`
	UnallocatedDiskBytes     int64    `json:"unallocated_disk_bytes"`
	Stages                   []string `json:"stages"`
	RequiresUnlockCredential bool     `json:"requires_unlock_credential"`
	Irreversible             bool     `json:"irreversible"`
}
type Plan struct {
	ID                 string     `json:"id"`
	InstallationID     string     `json:"installation_id"`
	Operation          string     `json:"operation"`
	Parameters         Parameters `json:"parameters"`
	ResourceRevision   string     `json:"resource_revision"`
	IssuedAt           int64      `json:"issued_at"`
	ExpiresAt          int64      `json:"expires_at"`
	Digest             string     `json:"digest"`
	Review             Review     `json:"review"`
	ExecutionAvailable bool       `json:"execution_available"`
}

// Refusal exposes only fixed protocol codes, never a host exception or payload.
type Refusal struct{ Code string }

func (e *Refusal) Error() string { return "host plan unavailable" }

var reasons = map[string]bool{"invalid_request": true, "peer_not_authorized": true, "request_timeout": true, "host_unavailable": true, "plan_unavailable": true, "plan_expired": true, "resource_changed": true, "manager_busy": true, "journal_full": true}

type Client struct {
	dial  func(context.Context) (net.Conn, error)
	clock func() time.Time
	slots chan struct{}
}

// New always uses the fixed protected Unix endpoint. There is no configurable
// network address, proxy, request-selected path or non-Linux fallback.
func New() *Client {
	return &Client{dial: dialProtected, clock: time.Now, slots: make(chan struct{}, 4)}
}

func (c *Client) call(ctx context.Context, actor Actor, action string, fields map[string]any) (json.RawMessage, error) {
	if c == nil || c.dial == nil || c.clock == nil || c.slots == nil || !actor.valid() {
		return nil, ErrUnavailable
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return nil, &Refusal{Code: "manager_busy"}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req := map[string]any{"schema": 1, "action": action, "actor": actor.wire()}
	for key, value := range fields {
		req[key] = value
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > maxRequest {
		return nil, ErrUnavailable
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return nil, ErrUnavailable
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	if _, err = io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return nil, ErrUnavailable
	}
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok || half.CloseWrite() != nil {
		return nil, ErrUnavailable
	}
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, ErrUnavailable
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxResponse {
		return nil, ErrUnavailable
	}
	response := make([]byte, n)
	if _, err = io.ReadFull(conn, response); err != nil {
		return nil, ErrUnavailable
	}
	var extra [1]byte
	if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if !uniqueJSON(response) {
		return nil, ErrUnavailable
	}
	var envelope struct {
		Schema int             `json:"schema"`
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
		Reason string          `json:"reason"`
	}
	if json.Unmarshal(response, &envelope) != nil || envelope.Schema != 1 {
		return nil, ErrUnavailable
	}
	if envelope.Status == "unavailable" {
		if _, err := object(response, "schema", "status", "reason"); err != nil || !reasons[envelope.Reason] {
			return nil, ErrUnavailable
		}
		return nil, &Refusal{Code: envelope.Reason}
	}
	if envelope.Status != "ok" {
		return nil, ErrUnavailable
	}
	if _, err := object(response, "schema", "status", "data"); err != nil {
		return nil, ErrUnavailable
	}
	return envelope.Data, nil
}

func (c *Client) Capabilities(ctx context.Context, actor Actor) (Capabilities, error) {
	raw, err := c.call(ctx, actor, "capabilities", nil)
	if err != nil {
		return Capabilities{}, err
	}
	fields, err := object(raw, "control", "execution_available", "pool_id", "operations")
	var value Capabilities
	if err != nil || json.Unmarshal(raw, &value) != nil || value.Control != "read_only" || value.ExecutionAvailable || !ValidUUID(value.PoolID) || len(value.Operations) != 1 {
		return Capabilities{}, ErrUnavailable
	}
	var entries []json.RawMessage
	if json.Unmarshal(fields["operations"], &entries) != nil {
		return Capabilities{}, ErrUnavailable
	}
	if _, err := object(entries[0], "operation", "planning_available", "execution_available", "reason"); err != nil {
		return Capabilities{}, ErrUnavailable
	}
	op := value.Operations[0]
	if op.Operation != "storage.grow" || !op.PlanningAvailable || op.ExecutionAvailable || op.Reason != "execution_not_qualified" {
		return Capabilities{}, ErrUnavailable
	}
	return value, nil
}

func ValidUUID(value string) bool {
	return uuidPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}
func ValidDigest(value string) bool { return digestPattern.MatchString(value) }

func (c *Client) CreatePlan(ctx context.Context, actor Actor, poolID string) (Plan, error) {
	if !ValidUUID(poolID) {
		return Plan{}, &Refusal{Code: "invalid_request"}
	}
	raw, err := c.call(ctx, actor, "plan.create", map[string]any{"operation": "storage.grow", "parameters": Parameters{poolID}})
	if err != nil {
		return Plan{}, err
	}
	p, err := c.plan(raw, actor)
	if err != nil || p.Parameters.PoolID != poolID {
		return Plan{}, ErrUnavailable
	}
	return p, nil
}
func (c *Client) LookupPlan(ctx context.Context, actor Actor, id, digest string) (Plan, error) {
	if !ValidUUID(id) || !ValidDigest(digest) {
		return Plan{}, &Refusal{Code: "invalid_request"}
	}
	raw, err := c.call(ctx, actor, "plan.lookup", map[string]any{"plan_id": id, "plan_digest": digest})
	if err != nil {
		return Plan{}, err
	}
	p, err := c.plan(raw, actor)
	if err != nil || p.ID != id || p.Digest != digest {
		return Plan{}, ErrUnavailable
	}
	return p, nil
}

func (c *Client) plan(raw []byte, actor Actor) (Plan, error) {
	fields, err := object(raw, "id", "installation_id", "operation", "parameters", "resource_revision", "issued_at", "expires_at", "digest", "review", "execution_available")
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	if _, err = object(fields["parameters"], "pool_id"); err != nil {
		return Plan{}, ErrUnavailable
	}
	if _, err = object(fields["review"], "current_bytes", "presented_bytes", "unallocated_disk_bytes", "stages", "requires_unlock_credential", "irreversible"); err != nil {
		return Plan{}, ErrUnavailable
	}
	var p Plan
	if json.Unmarshal(raw, &p) != nil || !ValidUUID(p.ID) || !ValidUUID(p.InstallationID) || !ValidUUID(p.Parameters.PoolID) || !ValidDigest(p.ResourceRevision) || !ValidDigest(p.Digest) || p.Operation != "storage.grow" || p.ExecutionAvailable {
		return Plan{}, ErrUnavailable
	}
	now := c.clock().Unix()
	if p.IssuedAt <= 0 || p.IssuedAt > now+5 || p.ExpiresAt <= now || p.ExpiresAt-p.IssuedAt < 30 || p.ExpiresAt-p.IssuedAt > 300 {
		return Plan{}, ErrUnavailable
	}
	r := p.Review
	if r.CurrentBytes <= 0 || r.PresentedBytes < r.CurrentBytes || r.PresentedBytes > 1<<53-1 || r.UnallocatedDiskBytes < 0 || r.UnallocatedDiskBytes > r.PresentedBytes || r.Stages == nil || len(r.Stages) > 5 || !r.Irreversible {
		return Plan{}, ErrUnavailable
	}
	order := map[string]int{"partition": 1, "luks": 2, "pv": 3, "lv": 4, "xfs": 5}
	last := 0
	unlock := false
	for _, stage := range r.Stages {
		if order[stage] <= last {
			return Plan{}, ErrUnavailable
		}
		last = order[stage]
		unlock = unlock || stage == "luks"
	}
	if r.RequiresUnlockCredential != unlock {
		return Plan{}, ErrUnavailable
	}
	expected := hash(map[string]any{"id": p.ID, "installation_id": p.InstallationID, "actor": actor.wire(), "operation": p.Operation, "parameters": p.Parameters, "resource_revision": p.ResourceRevision, "issued_at": p.IssuedAt, "expires_at": p.ExpiresAt})
	if p.Digest != expected {
		return Plan{}, ErrUnavailable
	}
	return p, nil
}

// Object shapes require every declared field, disallow extras and reject null;
// false/zero must not be invented by Go's ordinary missing-field defaults.
func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || len(value) != len(keys) {
		return nil, ErrUnavailable
	}
	for _, key := range keys {
		if v, ok := value[key]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, ErrUnavailable
		}
	}
	return value, nil
}

func uniqueJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maxResponse || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	left := 4096
	var check func(int) bool
	check = func(depth int) bool {
		left--
		if depth > 16 || left < 0 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		if delim != '{' && delim != '[' {
			return false
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, err := d.Token()
				name, ok := k.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
			}
			if !check(depth + 1) {
				return false
			}
		}
		_, err = d.Token()
		return err == nil
	}
	if !check(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
