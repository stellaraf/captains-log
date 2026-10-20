package panos

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// These fixtures follow the official default Syslog field lists. They are
// constructed examples, not evidence of a particular firewall release's output.
func TestConstructedGlobalProtectAndDecryption(t *testing.T) {
	p := NewParser(Options{Timezone: time.FixedZone("America/Phoenix", -7*60*60)})
	ingested := time.Date(2026, 10, 1, 12, 0, 1, 0, time.UTC)
	for _, family := range []string{"globalprotect", "decryption"} {
		for _, outcome := range []string{"success-ipv4", "failure-ipv6"} {
			t.Run(family+"/"+outcome, func(t *testing.T) {
				failed := outcome == "failure-ipv6"
				raw := fixture(t, "constructed-"+family+"-"+outcome+".log")
				e := p.Parse(raw, "[2001:db8::1]:6514", ingested)
				if e.ParseStatus != "parsed" || e.ParseError != "" || e.LogType != family || e.WireType != strings.ToUpper(family) || e.SchemaID != "panos-"+family+"-v1" {
					t.Fatalf("classification: %+v", e)
				}
				if e.Serial != "012345678901" || e.SenderIP != "2001:db8::1" || e.PANOSVersion != "" || e.ParserVersion != ParserVersion || e.SchemaVersion != e.SchemaID || e.Raw != string(raw) || e.RawBase64 != "" {
					t.Fatalf("raw/provenance: %+v", e)
				}
				if e.ReceivedAt == nil || e.ReceivedAt.Format(time.RFC3339Nano) != "2026-10-01T12:00:00.123456Z" || e.GeneratedAt == nil || e.GeneratedAt.Format(time.RFC3339) != "2026-10-01T11:59:58Z" || !e.IngestedAt.Equal(ingested) {
					t.Fatalf("timestamps: %+v", e)
				}
				if e.Bytes != 0 || e.BytesSent != 0 || e.BytesReceived != 0 || e.Packets != 0 {
					t.Fatal("non-Traffic fields became Traffic counters")
				}
				want := map[string]string{}
				width, extras := 52, 4
				wantExtras := []string{"3", "gp-cluster", `extension, "future"`, "tail-51"}
				if family == "globalprotect" {
					ip, status, reason, errorText, errorCode := "192.0.2.15", "success", "authentication succeeded", "", "0"
					if failed {
						ip, status, reason, errorText, errorCode = "2001:db8::16", "failure", "authentication failed", "invalid credentials", "1001"
					}
					if e.SrcIP != ip || e.Action != status || e.Description != `Fixture, "login" result` || e.SrcUser != `EXAMPLE\fixture` || e.DeviceName != "gp-fw" || e.VSYS != "vsys3" || e.DstIP != "" || e.SessionID != 0 {
						t.Fatalf("GlobalProtect normalization: %+v", e)
					}
					want = map[string]string{
						"event_id": "gateway-auth", "stage": "login", "authentication_method": "SAML", "tunnel_type": "SSL",
						"source_region": "US", "machine_name": "client.example.invalid", "private_ip": "198.51.100.17", "private_ipv6": "2001:db8:1::18",
						"host_id": "host-19", "client_serial": "client-20", "client_version": "6.3.1", "client_os": "Windows", "client_os_version": "11",
						"repeat_count": "2", "reason": reason, "error": errorText, "location": "external", "duration": "123", "connect_method": "on-demand", "error_code": errorCode,
						"portal": "portal.example.invalid", "sequence": "18446744073709551615", "action_flags": "0x0", "gateway": "gateway.example.invalid", "vsys_name": "Remote users",
						"csv_037": "manual", "csv_038": "38", "csv_039": "39", "csv_040": "gateway-a;gateway-b", "csv_042": "42", "csv_045": "45", "csv_048": "3", "csv_049": "gp-cluster",
					}
				} else {
					width, extras = 109, 12
					wantExtras = []string{"4", "encrypted-tunnel", "networking", "browser-based", "4", "pervasive-use", "ssl", "no", "yes", "decrypt-cluster", `extension, "future"`, "tail-108"}
					src, dst, natSrc, natDst, action, trust, description := "192.0.2.7", "198.51.100.8", "203.0.113.9", "203.0.113.10", "allow", "trusted", ""
					errorType := ""
					if failed {
						src, dst, natSrc, natDst, action, trust, description = "2001:db8::7", "2001:db8::8", "2001:db8:1::9", "2001:db8:1::10", "deny", "untrusted", `Certificate, "untrusted" issuer`
						errorType = "Certificate"
					}
					if e.SrcIP != src || e.DstIP != dst || e.NATSrcIP != natSrc || e.NATDstIP != natDst || e.SrcPort != 65535 || e.DstPort != 443 || e.SessionID != ^uint64(0) || e.Action != action || e.Description != description {
						t.Fatalf("Decryption network/outcome: %+v", e)
					}
					if e.Rule != `Fixture, "TLS" rule` || e.SrcUser != `EXAMPLE\source` || e.DstUser != `EXAMPLE\destination` || e.App != "ssl" || e.VSYS != "vsys4" || e.SrcZone != "trust" || e.DstZone != "untrust" || e.DeviceName != "decrypt-fw" {
						t.Fatalf("Decryption identity: %+v", e)
					}
					want = map[string]string{
						"config_version": "2561", "repeat_count": "2", "flags": "0x40000000", "tunnel": "N/A", "csv_045": errorType,
						"client_handshake_stage": "ClientHello", "server_handshake_stage": "Certificate", "tls_version": "TLSv1.3", "key_exchange": "ECDHE", "encryption_algorithm": "AES_128_GCM", "hash_algorithm": "SHA256",
						"policy_name": "Fixture TLS policy", "elliptic_curve": "secp256r1", "root_status": trust, "chain_status": trust, "proxy_type": "Forward", "certificate_serial": "1234567890abcdef", "fingerprint": strings.Repeat("a", 64),
						"subject_common_name": "service.example.invalid", "issuer_common_name": "issuer.example.invalid", "root_common_name": "root.example.invalid", "sni": "service.example.invalid",
						"source_hostname": "source.example.invalid", "destination_hostname": "destination.example.invalid", "sequence": "18446744073709551615", "action_flags": "0x0", "vsys_name": "TLS inspection",
						"log_forwarding_profile": "FixtureForwarding", "inbound_interface": "ethernet1/1", "outbound_interface": "ethernet1/2", "nat_src_port": "49152", "nat_dst_port": "8443", "protocol": "tcp",
						"rule_uuid": "33333333-3333-4333-8333-333333333333", "csv_051": "2026/01/01 00:00:00", "csv_052": "2027/01/01 00:00:00", "csv_059": "0x0", "csv_065": "container-65", "csv_097": "4", "csv_106": "decrypt-cluster",
					}
				}
				for key, value := range want {
					if e.Fields[key] != value {
						t.Errorf("%s = %q; want %q", key, e.Fields[key], value)
					}
				}
				if len(e.ExtraFields) != extras || !slices.Equal(e.ExtraFields, wantExtras) {
					t.Fatalf("extension preservation: %+v", e.ExtraFields)
				}
				values, err := csv.NewReader(bytes.NewReader(raw)).Read()
				if err != nil {
					t.Fatal(err)
				}
				for index, value := range values {
					if got := e.Fields[fmt.Sprintf("csv_%03d", index)]; got != value {
						t.Errorf("raw field %d: got %q, want %q", index, got, value)
					}
				}
				csvFields := 0
				for name := range e.Fields {
					if strings.HasPrefix(name, "csv_") {
						csvFields++
					}
				}
				if csvFields != width {
					t.Fatalf("raw field count = %d; want %d", csvFields, width)
				}
			})
		}
	}
}

func TestConstructedSecurityLogTypedErrorsPreserveEvidence(t *testing.T) {
	cases := []struct {
		family string
		index  int
		value  string
		error  string
	}{
		{"globalprotect", 15, "not-an-address", "invalid src_ip"},
		{"globalprotect", 16, "not-an-address", "invalid public_ipv6"},
		{"globalprotect", 36, "not-a-time", "invalid high resolution timestamp"},
		{"decryption", 7, "not-an-address", "invalid src_ip"},
		{"decryption", 8, "not-an-address", "invalid dst_ip"},
		{"decryption", 9, "not-an-address", "invalid nat_src_ip"},
		{"decryption", 10, "not-an-address", "invalid nat_dst_ip"},
		{"decryption", 22, "18446744073709551616", "invalid session_id"},
		{"decryption", 24, "65536", "invalid src_port"},
		{"decryption", 25, "-1", "invalid dst_port"},
		{"decryption", 72, "not-a-time", "invalid high resolution timestamp"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%d", tc.family, tc.index), func(t *testing.T) {
			variant := "success-ipv4"
			if tc.family == "globalprotect" && tc.index == 16 {
				variant = "failure-ipv6"
			}
			values, err := csv.NewReader(bytes.NewReader(fixture(t, "constructed-"+tc.family+"-"+variant+".log"))).Read()
			if err != nil {
				t.Fatal(err)
			}
			values[tc.index] = tc.value
			var raw bytes.Buffer
			w := csv.NewWriter(&raw)
			if err := w.Write(values); err != nil {
				t.Fatal(err)
			}
			w.Flush()
			if err := w.Error(); err != nil {
				t.Fatal(err)
			}
			e := Parse(raw.Bytes(), "192.0.2.1:6514", time.Now())
			if e.ParseStatus != "partial" || e.ParseError != tc.error || e.LogType != tc.family || e.Raw != raw.String() || e.Fields[fmt.Sprintf("csv_%03d", tc.index)] != tc.value {
				t.Fatalf("typed error lost original evidence: %+v", e)
			}
		})
	}
}

func TestConstructedGlobalProtectDualStack(t *testing.T) {
	values, err := csv.NewReader(bytes.NewReader(fixture(t, "constructed-globalprotect-success-ipv4.log"))).Read()
	if err != nil {
		t.Fatal(err)
	}
	values[16] = "2001:db8::16"
	var raw bytes.Buffer
	w := csv.NewWriter(&raw)
	if err := w.Write(values); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatal(err)
	}
	e := Parse(raw.Bytes(), "192.0.2.1:6514", time.Now())
	if e.ParseStatus != "parsed" || e.SrcIP != "192.0.2.15" || e.Fields["public_ipv6"] != "2001:db8::16" || e.Raw != raw.String() {
		t.Fatalf("dual-stack source selection or evidence changed: %+v", e)
	}
}
