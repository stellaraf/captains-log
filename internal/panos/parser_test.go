package panos

import (
	"bytes"
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestTrafficEvidenceAndExtendedTimestamp(t *testing.T) {
	raw := fixture(t, "traffic.log")
	e := Parse(raw, "[2001:db8::1]:5514", time.Date(2026, 9, 7, 21, 0, 1, 0, time.UTC))
	if e.ParseStatus != "parsed" {
		t.Fatalf("parse: %+v", e)
	}
	if e.Rule != "Allow DNS, \"Production\"" || e.SrcUser != `EXAMPLE\alice` {
		t.Fatalf("CSV quoting or backslash corrupted: %q %q", e.Rule, e.SrcUser)
	}
	if e.SrcIP != "192.0.2.20" || e.DstIP != "2001:db8::53" || e.DstPort != 53 || e.Bytes != 1500 || e.BytesSent != 600 || e.BytesReceived != 900 || e.Packets != 12 || e.SessionID != 987654321 {
		t.Fatalf("network mismatch: %+v", e)
	}
	if e.DeviceName != "edge-phx" || e.Serial != "012345678901" || e.LogType != "traffic" || e.WireType != "TRAFFIC" || e.SenderIP != "2001:db8::1" {
		t.Fatalf("provenance mismatch: %+v", e)
	}
	if e.ReceivedAt.Format(time.RFC3339Nano) != "2026-09-07T21:00:00.123Z" {
		t.Fatal(e.ReceivedAt)
	}
	if e.PANOSVersion != "" || e.SchemaID == "" || e.SchemaVersion != e.SchemaID || e.ParserVersion == "" || e.Raw != string(raw) {
		t.Fatal("parser metadata not preserved")
	}
}
func TestThreatWireCategoryAndRFC5424(t *testing.T) {
	raw := fixture(t, "url.log")
	e := Parse(raw, "192.0.2.1", time.Now())
	if e.ParseStatus != "parsed" {
		t.Fatal(e.ParseError)
	}
	if e.LogType != "url" || e.WireType != "THREAT" || e.Description != `https://example.test/a,b?q="value"` {
		t.Fatalf("%+v", e)
	}
	for _, tc := range []struct{ sub, threat, want string }{{"wildfire", "", "wildfire"}, {"wildfire-virus", "", "threat"}, {"spyware", "dns-malware", "dns"}, {"file", "", "data"}, {"data", "", "data"}, {"vulnerability", "", "threat"}} {
		if got := category("THREAT", tc.sub, tc.threat); got != tc.want {
			t.Fatalf("category %s: %s", tc.sub, got)
		}
	}
}
func TestManagementAndConfigurationLayouts(t *testing.T) {
	for _, tc := range []struct{ file, typ, schema string }{{"system.log", "system", "panos-system-v1"}, {"config.log", "configuration", "panos-config-default-v1"}, {"config-details.log", "configuration", "panos-config-details-v1"}} {
		t.Run(tc.file, func(t *testing.T) {
			e := Parse(fixture(t, tc.file), "192.0.2.1", time.Now())
			if e.ParseStatus != "parsed" || e.LogType != tc.typ || e.SchemaID != tc.schema || e.DeviceName != "edge-phx" {
				t.Fatalf("%+v", e)
			}
		})
	}
}

func TestAdvancedDNSThreatCategories(t *testing.T) {
	// This is a controlled variation of the sanitized PA-1410 native Threat
	// fixture, not a claim that the appliance captured adns-* on that firewall.
	body, _, err := envelope(string(fixture(t, "pa1410-12.1-dns.log")))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := csv.NewReader(strings.NewReader(body)).Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ category, want string }{
		{"dns-malware", "dns"}, {"adns-hijacking", "dns"},
		{"adns-dnsmisconfig", "dns"}, {"adns-benign", "dns"},
		{"ADNS-C2", "dns"}, {"spyware", "threat"},
		{"not-adns-malware", "threat"}, {"adns", "threat"},
	} {
		t.Run(tc.category, func(t *testing.T) {
			fields[69] = tc.category
			var out bytes.Buffer
			writer := csv.NewWriter(&out)
			if err := writer.Write(fields); err != nil {
				t.Fatal(err)
			}
			writer.Flush()
			e := Parse(out.Bytes(), "192.0.2.1", time.Now())
			if e.ParseStatus != "parsed" || e.LogType != tc.want || e.WireType != "THREAT" || e.Subtype != "spyware" || e.Fields["threat_category"] != tc.category || e.Raw != out.String() {
				t.Fatalf("category or evidence changed: %+v", e)
			}
		})
	}
	// Existing product-specific subtypes keep their distinct views.
	for _, tc := range []struct{ subtype, want string }{{"url", "url"}, {"wildfire", "wildfire"}, {"data", "data"}, {"file", "data"}, {"dlp", "data"}} {
		if got := category("THREAT", tc.subtype, "adns-malware"); got != tc.want {
			t.Fatalf("%s unexpectedly classified as %s", tc.subtype, got)
		}
	}
}
func TestPreserveMalformedUnrecognizedAndExtensions(t *testing.T) {
	for _, raw := range []string{"garbage", `1,2026/09/07 14:00:00,0123,TRAFFIC,end,0,2026/09/07 14:00:00,"unterminated`, `1,2026/09/07 14:00:00,0123,NEWFAMILY,a,0,2026/09/07 14:00:00,a`, "<999>invalid"} {
		e := Parse([]byte(raw), "192.0.2.1", time.Now())
		if e.ParseStatus == "parsed" || e.ParseError == "" || e.Raw != raw || e.SenderIP != "192.0.2.1" {
			t.Fatalf("lost failure evidence %+v", e)
		}
	}
	raw := append(fixture(t, "traffic.log"), []byte(",future-value,another-value")...)
	e := Parse(raw, "", time.Now())
	if len(e.ExtraFields) != 2 || e.ExtraFields[0] != "future-value" || e.ParseStatus != "parsed" {
		t.Fatal(e)
	}
}
func TestTimestampTimezoneAndInvalidTypedValues(t *testing.T) {
	loc, err := time.LoadLocation("America/Phoenix")
	if err != nil {
		t.Fatal(err)
	}
	e := NewParser(Options{Timezone: loc, PANOSVersion: "11.2.6"}).Parse(fixture(t, "traffic.log"), "", time.Now())
	if e.GeneratedAt.Format(time.RFC3339) != "2026-09-07T20:59:58Z" || e.PANOSVersion != "11.2.6" || !strings.Contains(e.TimestampTimezone, "Phoenix") {
		t.Fatal(e)
	}
	body, _, _ := envelope(string(fixture(t, "traffic.log")))
	r := csv.NewReader(strings.NewReader(body))
	fields, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	fields[7] = "not-an-IP"
	fields[25] = "65536"
	fields[31] = "-1"
	var out bytes.Buffer
	w := csv.NewWriter(&out)
	w.Write(fields)
	w.Flush()
	bad := Parse(out.Bytes(), "", time.Now())
	if bad.ParseStatus != "partial" || bad.SrcIP != "" || bad.Bytes != 0 || bad.DstPort != 0 || !strings.Contains(bad.ParseError, "src_ip") {
		t.Fatal(bad)
	}
}
func TestUnknownVersionAndTruncatedCore(t *testing.T) {
	raw := []byte("1,2026/09/07 14:00:00,0123,TRAFFIC,end,12.2,2026/09/07 14:00:00,192.0.2.2")
	e := Parse(raw, "", time.Now())
	if e.ParseStatus != "partial" || e.PANOSVersion != "" || e.Raw != string(raw) {
		t.Fatal(e)
	}
}
func TestRawInvalidUTF8Retained(t *testing.T) {
	e := Parse([]byte{0xff, 0xfe}, "", time.Now())
	if e.RawBase64 != "//4=" {
		t.Fatal(e)
	}
}
func TestSchemasDefensiveCopy(t *testing.T) {
	s := Schemas()
	original := s[0].Fields["src_ip"]
	s[0].Fields["src_ip"] = 999
	if Schemas()[0].Fields["src_ip"] != original {
		t.Fatal("registry mutated")
	}
}
func FuzzParserNeverLosesRaw(f *testing.F) {
	f.Add([]byte("invalid"))
	f.Add([]byte("<14>Sep  7 14:00:00 edge 1,now,serial,TRAFFIC,end,0,now"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e := Parse(b, "192.0.2.1", time.Unix(0, 0))
		if e.Raw != string(b) {
			t.Fatal("raw not preserved")
		}
	})
}
func BenchmarkTrafficParser(b *testing.B) {
	raw, err := os.ReadFile("testdata/traffic.log")
	if err != nil {
		b.Fatal(err)
	}
	p := NewParser(Options{})
	now := time.Now()
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		p.Parse(raw, "192.0.2.1", now)
	}
}

func TestDistinctAdditionalFamilyPrefixes(t *testing.T) {
	cases := []struct{ raw, typ, src, user, description string }{
		{`1,2026/09/07 14:00:00,0123,HIP-MATCH,0,0,2026/09/07 14:00:00,EXAMPLE\alice,vsys2,workstation,Linux,192.0.2.33,Managed endpoint,1,profile`, "hip", "192.0.2.33", `EXAMPLE\alice`, "Managed endpoint"},
		{`1,2026/09/07 14:00:00,0123,IPTAG,0,0,2026/09/07 14:00:00,vsys2,2001:db8::3,Quarantine,register`, "iptag", "2001:db8::3", "", "Quarantine"},
		{`1,2026/09/07 14:00:00,0123,AUTHENTICATION,auth,0,2026/09/07 14:00:00,vsys2,192.0.2.33,alice,EXAMPLE\alice,,MFA Policy,1,123,Local,Forward,Local authentication,Authentication succeeded,web,success`, "authentication", "192.0.2.33", "alice", "Authentication succeeded"},
		{`1,2026/09/07 14:00:00,0123,USERID,login,0,2026/09/07 14:00:00,vsys2,192.0.2.33,alice,DC01,login`, "userid", "192.0.2.33", "alice", ""},
	}
	for _, tc := range cases {
		e := Parse([]byte(tc.raw), "192.0.2.1", time.Now())
		if e.ParseStatus != "parsed" || e.LogType != tc.typ || e.SrcIP != tc.src || e.SrcUser != tc.user || e.Description != tc.description || e.VSYS != "vsys2" {
			t.Fatalf("%+v", e)
		}
	}
	raw := strings.Replace(string(fixture(t, "traffic.log")), ",TRAFFIC,end,", ",DECRYPTION,0,", 1)
	// Decryption's extension differs completely from Traffic after the network
	// prefix; use only the documented common prefix for this compatibility case.
	body, _, err := envelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(body))
	v, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write(v[:31])
	w.Flush()
	e := Parse(b.Bytes(), "", time.Now())
	if e.LogType != "decryption" || e.App != "dns" || e.DstPort != 53 || e.Bytes != 0 || e.ParseStatus != "parsed" {
		t.Fatal(e)
	}
}

func TestSanitizedNativePA1410PANOS121Layouts(t *testing.T) {
	location, err := time.LoadLocation("US/Pacific")
	if err != nil {
		t.Fatal(err)
	}
	parser := NewParser(Options{Timezone: location, PANOSVersion: "12.1.4-h8"})
	for _, tc := range []struct {
		file, typ, subtype, action, time string
		count                            int
	}{{"pa1410-12.1-traffic.log", "traffic", "end", "allow", "2026-09-07T22:00:00.123Z", 130}, {"pa1410-12.1-dns.log", "dns", "spyware", "drop", "2026-09-07T22:00:00.456Z", 140}} {
		e := parser.Parse(fixture(t, tc.file), "192.0.2.1", time.Date(2026, 9, 7, 22, 0, 1, 0, time.UTC))
		if e.ParseStatus != "parsed" {
			t.Fatal(e.ParseError)
		}
		if e.LogType != tc.typ || e.Subtype != tc.subtype || e.App != "dns-base" || e.Action != tc.action || e.SrcIP != "192.0.2.20" || e.DstIP != "2001:db8::53" || e.SrcPort != 54000 || e.DstPort != 53 || e.DeviceName != "lab-fw" {
			t.Fatalf("native normalization mismatch: %+v", e)
		}
		if e.ReceivedAt.Format(time.RFC3339Nano) != tc.time || e.GeneratedAt.Format(time.RFC3339) != "2026-09-07T21:59:58Z" || e.PANOSVersion != "12.1.4-h8" {
			t.Fatal("native timestamps/version mismatch")
		}
		body, _, _ := envelope(e.Raw)
		fields, err := csv.NewReader(strings.NewReader(body)).Read()
		if err != nil || len(fields) != tc.count {
			t.Fatalf("native layout count changed: %d %v", len(fields), err)
		}
		if tc.typ == "traffic" && (e.Bytes != 1500 || e.BytesSent != 600 || e.BytesReceived != 900 || e.Packets != 12 || e.SessionID != 4242) {
			t.Fatal("traffic counters shifted")
		}
		if tc.typ == "dns" && (!strings.HasPrefix(e.Fields["threat_category"], "dns-") || e.Description != "test.example" || e.Fields["threat_id"] != "Sanitized DNS signature(123456789)") {
			t.Fatal("threat fields shifted")
		}
	}
}
