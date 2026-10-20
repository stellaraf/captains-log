package panos

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type identityFixture struct {
	Filename      string            `json:"filename"`
	OfficialWidth int               `json:"official_width"`
	ActualWidth   int               `json:"actual_width"`
	CSV           []string          `json:"all_csv_fields"`
	Named         map[string]string `json:"named_fields"`
	Extra         []string          `json:"extra_fields"`
	Normalized    map[string]any    `json:"normalized"`
}

func identityFixtures(t *testing.T) []identityFixture {
	t.Helper()
	var oracle struct {
		Fixtures []identityFixture `json:"fixtures"`
	}
	if err := json.Unmarshal(fixture(t, "constructed-identity-expected.json"), &oracle); err != nil {
		t.Fatal(err)
	}
	if len(oracle.Fixtures) != 11 {
		t.Fatalf("expected eleven reviewed identity fixtures, got %d", len(oracle.Fixtures))
	}
	return oracle.Fixtures
}

func identityParser() *Parser {
	return NewParser(Options{Timezone: time.FixedZone("America/Phoenix", -7*60*60)})
}

func identityCSV(t *testing.T, values []string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write(values); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func assertIdentityRawFields(t *testing.T, e Event, raw []byte, values []string) {
	t.Helper()
	if e.Raw != string(raw) || e.RawBase64 != "" {
		t.Fatal("original UTF-8 evidence changed")
	}
	count := 0
	for k := range e.Fields {
		if strings.HasPrefix(k, "csv_") {
			count++
		}
	}
	if count != len(values) {
		t.Fatalf("raw field count %d, want %d", count, len(values))
	}
	for i, value := range values {
		key := fmt.Sprintf("csv_%03d", i)
		if got, exists := e.Fields[key]; !exists || got != value {
			t.Errorf("%s = %q (exists %t), want %q", key, got, exists, value)
		}
	}
}

// The literal oracle follows the official field lists. It does not call
// Schemas or derive expected normalized values from the parser under test.
func TestConstructedIdentityFamilies(t *testing.T) {
	ingested := time.Date(2026, 10, 1, 12, 0, 1, 0, time.UTC)
	for _, tc := range identityFixtures(t) {
		t.Run(tc.Filename, func(t *testing.T) {
			body := fixture(t, tc.Filename)
			values, err := csv.NewReader(bytes.NewReader(body)).Read()
			if err != nil || len(values) != tc.ActualWidth || tc.ActualWidth != tc.OfficialWidth+2 || !slices.Equal(values, tc.CSV) {
				t.Fatalf("fixture differs from reviewed full-width CSV: %v", err)
			}
			for _, envelope := range []struct{ name, prefix string }{
				{"raw", ""},
				{"rfc3164", "<14>Oct  1 05:00:00 relay.example.invalid "},
				{"rfc5424", "<14>1 2026-10-01T12:00:00Z relay.example.invalid panos - - - "},
			} {
				t.Run(envelope.name, func(t *testing.T) {
					raw := append([]byte(envelope.prefix), body...)
					e := identityParser().Parse(raw, "[2001:db8::1]:6514", ingested)
					assertIdentityRawFields(t, e, raw, tc.CSV)
					if e.ID == "" || !e.IngestedAt.Equal(ingested) || e.ParserVersion != ParserVersion || e.SchemaVersion != e.SchemaID {
						t.Fatalf("provenance mismatch: %+v", e)
					}
					for key, want := range tc.Named {
						if got, exists := e.Fields[key]; !exists || got != want {
							t.Errorf("named %s = %q (exists %t), want %q", key, got, exists, want)
						}
					}
					if !slices.Equal(e.ExtraFields, tc.Extra) {
						t.Errorf("ordered suffix = %#v, want %#v", e.ExtraFields, tc.Extra)
					}
					for key, want := range tc.Normalized {
						field := reflect.ValueOf(e).FieldByName(key)
						if !field.IsValid() {
							t.Fatalf("oracle references absent Event field %q", key)
						}
						encoded, err := json.Marshal(field.Interface())
						if err != nil {
							t.Fatal(err)
						}
						var got any
						if err := json.Unmarshal(encoded, &got); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(got, want) {
							t.Errorf("normalized %s = %#v, want %#v", key, got, want)
						}
					}
				})
			}
		})
	}
}

func TestIdentityFamilyTypedErrorsPreserveEvidence(t *testing.T) {
	first := map[string]identityFixture{}
	for _, tc := range identityFixtures(t) {
		wire := tc.CSV[3]
		if _, exists := first[wire]; !exists {
			first[wire] = tc
		}
	}
	cases := []struct {
		wire  string
		index int
		value string
		error string
	}{
		{"HIP-MATCH", 11, "not-an-address", "invalid src_ip"},
		{"IPTAG", 8, "not-an-address", "invalid src_ip"},
		{"USERID", 8, "not-an-address", "invalid src_ip"},
		{"AUTHENTICATION", 8, "not-an-address", "invalid src_ip"},
		{"HIP-MATCH", 26, "not-an-address", "invalid src_ipv6"},
		{"HIP-MATCH", 30, "not-a-time", "invalid high resolution timestamp"},
		{"IPTAG", 25, "not-a-time", "invalid high resolution timestamp"},
		{"USERID", 33, "not-a-time", "invalid high resolution timestamp"},
		{"AUTHENTICATION", 33, "not-a-time", "invalid high resolution timestamp"},
		{"USERID", 14, "65536", "invalid src_port"},
		{"USERID", 14, "-1", "invalid src_port"},
		{"USERID", 14, "not-a-number", "invalid src_port"},
		{"USERID", 15, "65536", "invalid dst_port"},
		{"USERID", 15, "-1", "invalid dst_port"},
		{"USERID", 15, "not-a-number", "invalid dst_port"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%d/%s", tc.wire, tc.index, tc.value), func(t *testing.T) {
			base := first[tc.wire]
			values := slices.Clone(base.CSV)
			if tc.wire == "HIP-MATCH" && tc.index == 26 {
				values[11] = ""
			}
			values[tc.index] = tc.value
			raw := identityCSV(t, values)
			e := identityParser().Parse(raw, "192.0.2.1", time.Now())
			if e.ParseStatus != "partial" || e.ParseError != tc.error || e.LogType != base.Normalized["LogType"] || e.WireType != tc.wire || e.Serial != base.CSV[2] {
				t.Fatalf("typed error or unaffected identity: %+v", e)
			}
			assertIdentityRawFields(t, e, raw, values)
			if !slices.Equal(e.ExtraFields, base.Extra) {
				t.Fatal("typed failure lost trailing evidence")
			}
		})
	}
}

func TestIdentityFamilyCoreBoundaries(t *testing.T) {
	minimum := map[string]int{"HIP-MATCH": 15, "IPTAG": 11, "USERID": 12, "AUTHENTICATION": 21}
	lastNamedWidth := map[string]int{"HIP-MATCH": 31, "IPTAG": 26, "USERID": 34, "AUTHENTICATION": 41}
	seen := map[string]bool{}
	for _, tc := range identityFixtures(t) {
		wire := tc.CSV[3]
		if seen[wire] {
			continue
		}
		seen[wire] = true
		for _, width := range []int{minimum[wire] - 1, minimum[wire], lastNamedWidth[wire], tc.OfficialWidth, tc.ActualWidth} {
			t.Run(fmt.Sprintf("%s/%d", wire, width), func(t *testing.T) {
				values := tc.CSV[:width]
				raw := identityCSV(t, values)
				e := identityParser().Parse(raw, "192.0.2.1", time.Now())
				wantStatus, wantError := "parsed", ""
				if width < minimum[wire] {
					wantStatus = "partial"
					wantError = fmt.Sprintf("%s core needs at least %d fields; received %d", wire, minimum[wire], width)
				}
				if e.ParseStatus != wantStatus || e.ParseError != wantError || e.LogType != tc.Normalized["LogType"] {
					t.Fatalf("prefix contract: %+v", e)
				}
				assertIdentityRawFields(t, e, raw, values)
			})
		}
	}
}

func TestIdentityFamilyCommonHeaderFailures(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range identityFixtures(t) {
		wire := tc.CSV[3]
		if seen[wire] {
			continue
		}
		seen[wire] = true
		for _, invalid := range []struct {
			name, value, error string
			index              int
		}{
			{"missing-serial", "", "missing firewall serial", 2},
			{"missing-received", "", "invalid or missing firewall receive timestamp", 1},
			{"invalid-received", "not-a-time", "invalid or missing firewall receive timestamp", 1},
			{"missing-generated", "", "invalid or missing generated timestamp", 6},
			{"invalid-generated", "not-a-time", "invalid or missing generated timestamp", 6},
		} {
			t.Run(wire+"/"+invalid.name, func(t *testing.T) {
				values := slices.Clone(tc.CSV)
				values[invalid.index] = invalid.value
				raw := identityCSV(t, values)
				e := identityParser().Parse(raw, "192.0.2.1", time.Now())
				if e.ParseStatus != "partial" || e.ParseError != invalid.error || e.LogType != tc.Normalized["LogType"] {
					t.Fatalf("malformed header: %+v", e)
				}
				assertIdentityRawFields(t, e, raw, values)
				if !slices.Equal(e.ExtraFields, tc.Extra) {
					t.Fatal("malformed header lost trailing evidence")
				}
			})
		}
		t.Run(wire+"/unsupported-wire", func(t *testing.T) {
			values := slices.Clone(tc.CSV)
			values[3] = "UNSUPPORTED-IDENTITY"
			raw := identityCSV(t, values)
			e := identityParser().Parse(raw, "192.0.2.1", time.Now())
			if e.ParseStatus != "unrecognized" || e.LogType != "unknown" || e.SchemaID != "" || !strings.Contains(e.ParseError, "UNSUPPORTED-IDENTITY") {
				t.Fatalf("unknown family was normalized: %+v", e)
			}
			assertIdentityRawFields(t, e, raw, values)
		})
	}
}

func TestHIPAddressPrecedenceWithoutSentinelInference(t *testing.T) {
	var base []string
	for _, tc := range identityFixtures(t) {
		if tc.CSV[3] == "HIP-MATCH" {
			base = tc.CSV
			break
		}
	}
	for _, tc := range []struct{ name, ipv4, want, status, error string }{
		{"blank-primary", "", "2001:db8::26", "parsed", ""},
		{"dual-stack", "192.0.2.11", "192.0.2.11", "parsed", ""},
		{"zero-primary", "0.0.0.0", "0.0.0.0", "parsed", ""},
		{"invalid-primary", "not-an-address", "2001:db8::26", "partial", "invalid src_ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := slices.Clone(base)
			values[11], values[26] = tc.ipv4, "2001:0db8:0:0::26"
			raw := identityCSV(t, values)
			e := identityParser().Parse(raw, "192.0.2.1", time.Now())
			if e.SrcIP != tc.want || e.ParseStatus != tc.status || e.ParseError != tc.error {
				t.Fatalf("HIP address precedence: %+v", e)
			}
			assertIdentityRawFields(t, e, raw, values)
		})
	}
}
