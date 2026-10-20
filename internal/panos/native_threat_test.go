package panos

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizedNativeThreatFileAndWildFireLayouts(t *testing.T) {
	// These layouts came from independently matched native/stored events.
	// Private values and the quoted filename/rule are replaced test data.
	cases := []struct {
		file, subtype, kind, action, category, severity, threatCategory, digest, fileType string
	}{
		{"pa1410-12.1-wildfire-allow.log", "wildfire", "wildfire", "allow", "benign", "informational", "N/A", strings.Repeat("a", 64), "archive"},
		{"pa1410-12.1-ml-virus-reset-both.log", "ml-virus", "threat", "reset-both", "computer-and-internet-info", "medium", "malicious-elf", "", ""},
		{"pa1410-12.1-file-alert.log", "file", "data", "alert", "computer-and-internet-info", "low", "N/A", "", ""},
		{"pa1410-12.1-file-deny.log", "file", "data", "deny", "computer-and-internet-info", "low", "N/A", "", ""},
	}
	parser := NewParser(Options{Timezone: time.FixedZone("America/Phoenix", -7*60*60), PANOSVersion: "12.1.4-h8"})
	ingested := time.Date(2026, 10, 1, 12, 0, 1, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			raw := fixture(t, tc.file)
			e := parser.Parse(raw, "[2001:db8::1]:6514", ingested)
			if e.ParseStatus != "parsed" || e.ParseError != "" || e.WireType != "THREAT" || e.Subtype != tc.subtype || e.LogType != tc.kind || e.Action != tc.action || e.Severity != tc.severity {
				t.Fatalf("classification: %+v", e)
			}
			if e.Description != `fixture, "payload".bin` || e.Rule != `Fixture, "Inspection"` || e.SrcUser != `EXAMPLE\fixture` {
				t.Fatalf("quoted evidence: %+v", e)
			}
			if e.SrcIP != "2001:db8::20" || e.DstIP != "192.0.2.30" || e.NATSrcIP != "2001:db8::20" || e.NATDstIP != "198.51.100.30" || e.SrcPort != 49152 || e.DstPort != 80 || e.SessionID != 987654321 {
				t.Fatalf("network fields: %+v", e)
			}
			if e.App != "web-browsing" || e.SrcZone != "trust" || e.DstZone != "untrust" || e.VSYS != "vsys1" || e.Serial != "012345678901" || e.DeviceName != "lab-fw" || e.SenderIP != "2001:db8::1" || e.PANOSVersion != "12.1.4-h8" || e.SchemaID != "panos-threat-core-v1" || e.SchemaVersion != e.SchemaID {
				t.Fatalf("session/provenance fields: %+v", e)
			}
			for name, want := range map[string]string{
				"category": tc.category, "threat_category": tc.threatCategory,
				"file_digest": tc.digest, "file_type": tc.fileType,
				"threat_id": "Example detection (999999)", "direction": "server-to-client", "protocol": "tcp",
				"sequence": "123456789012345", "log_forwarding_profile": "FixtureForwarding",
				"source_hostname": "source.example.invalid", "destination_hostname": "destination.example.invalid",
				"rule_uuid": "12345678-1234-4234-8234-123456789abc",
			} {
				if got := e.Fields[name]; got != want {
					t.Errorf("%s: got %q, want %q", name, got, want)
				}
			}
			if e.ReceivedAt == nil || e.ReceivedAt.Format(time.RFC3339Nano) != "2026-10-01T12:00:00.123456Z" || e.GeneratedAt == nil || e.GeneratedAt.Format(time.RFC3339) != "2026-10-01T11:59:58Z" || !e.IngestedAt.Equal(ingested) {
				t.Fatalf("timestamp fields: %+v", e)
			}
			if e.Raw != string(raw) || e.RawBase64 != "" || e.Bytes != 0 || e.BytesSent != 0 || e.BytesReceived != 0 || e.Packets != 0 {
				t.Fatal("native evidence changed or Threat fields interpreted as Traffic counters")
			}
			csvFields := 0
			for name := range e.Fields {
				if strings.HasPrefix(name, "csv_") {
					csvFields++
				}
			}
			if csvFields != 140 || len(e.ExtraFields) != 32 {
				t.Fatalf("native width/unknown suffix: %d/%d", csvFields, len(e.ExtraFields))
			}
			for _, value := range e.ExtraFields {
				if value != "" {
					t.Fatal("sanitized unknown suffix was not cleared")
				}
			}
		})
	}
}
