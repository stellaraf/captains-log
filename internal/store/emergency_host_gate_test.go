package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEmergencyHostGateConfiguration(t *testing.T) {
	if ValidateStorageMaintenancePath("", false) != nil {
		t.Fatal("local omission refused")
	}
	for _, path := range []string{"", "/tmp/gate.json", "relative/gate.json"} {
		if ValidateStorageMaintenancePath(path, true) == nil {
			t.Fatal("production fixed path bypass", path)
		}
	}
	s := &Store{StorageMaintenancePath: "/definitely-missing-owned-storage-gate/gate.json"}
	f := fakeEmergency()
	if s.emergencyStep(context.Background(), f, time.Now()) == nil {
		t.Fatal("worker reached nil database before host refusal")
	}
	if s.insertEmergencyGuarded(context.Background(), []map[string]any{{"id": "retained"}}) == nil {
		t.Fatal("delivery reached nil database before host refusal")
	}
}
func TestEmergencyHostGateStrictSchemaAndUnion(t *testing.T) {
	owner, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	idle := emergencyMaintenance{Schema: 1}
	held := emergencyMaintenance{Schema: 1, Held: true, DeliveryHeld: true, Operation: &owner}
	for _, pair := range [][2]emergencyMaintenance{{held, idle}, {idle, held}, {held, held}} {
		got, e := mergeEmergencyMaintenance(pair[0], pair[1])
		if e != nil || !got.Held || !got.DeliveryHeld || *got.Operation != owner {
			t.Fatal("host or DB hold was lost", got, e)
		}
	}
	foreign := held
	foreign.Operation = &other
	if _, e := mergeEmergencyMaintenance(held, foreign); e == nil {
		t.Fatal("foreign simultaneous owner accepted")
	}
	for _, raw := range []string{`{"schema":1,"held":false,"held":true,"delivery_held":false,"operation":null}`, `{"schema":1,"held":false,"delivery_held":false,"operation":null} {}`, `{"schema":true,"held":false,"delivery_held":false,"operation":null}`, `{"schema":1,"held":false,"delivery_held":false,"operation":null,"extra":0}`} {
		if _, e := parseEmergencyMaintenance([]byte(raw)); e == nil {
			t.Fatal("ambiguous host value accepted", raw)
		}
	}
	if _, e := parseEmergencyMaintenance([]byte(`{"schema":1,"held":false,"delivery_held":false,"operation":null}`)); e != nil {
		t.Fatal(e)
	}
}

// Child mode is invoked only by the Linux root fixture, with an unprivileged
// process identity and real root-owned immutable-public host files.
func TestEmergencyHostGateUnprivilegedChild(t *testing.T) {
	path := os.Getenv("CAPTAINSLOG_GATE_TEST_CHILD")
	if path == "" {
		return
	}
	gate, e := readHostStorageGate(path)
	want := os.Getenv("CAPTAINSLOG_GATE_TEST_WANT")
	if want == "refuse" {
		if e == nil {
			t.Fatal("unsafe host gate accepted")
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	if want == "hold" {
		idle := emergencyMaintenance{Schema: 1}
		combined, e := mergeEmergencyMaintenance(gate, idle)
		if e != nil || !combined.Held || !combined.DeliveryHeld {
			t.Fatal("restored idle DB bypasses retained host hold", e)
		}
	}
}
