package panos

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func newID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("system random generator unavailable")
	}
	return hex.EncodeToString(id[:])
}

func (p *Parser) Parse(raw []byte, sender string, ingestedAt time.Time) Event {
	if ingestedAt.IsZero() {
		ingestedAt = time.Now().UTC()
	}
	if h, _, err := net.SplitHostPort(sender); err == nil {
		sender = h
	}
	e := Event{ID: newID(), IngestedAt: ingestedAt.UTC(), SenderIP: sender, Raw: string(raw), ParserVersion: ParserVersion, LogType: "unknown", ParseStatus: "parsed", PANOSVersion: p.options.PANOSVersion, Fields: map[string]string{}, ExtraFields: []string{}}
	if !utf8.Valid(raw) {
		e.RawBase64 = base64.StdEncoding.EncodeToString(raw)
	}
	fail := func(s string) {
		if e.ParseError != "" {
			e.ParseError += "; "
		}
		e.ParseError += s
		e.ParseStatus = "partial"
	}
	body, hostname, err := envelope(string(raw))
	e.DeviceName = hostname
	if err != nil {
		e.ParseStatus = "failed"
		e.ParseError = err.Error()
		return e
	}
	r := csv.NewReader(strings.NewReader(body))
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	values, err := r.Read()
	if err != nil {
		// Only a suspicion: do not use these fragments to normalize untrusted CSV.
		fragments := strings.SplitN(body, ",", 6)
		if len(fragments) > 3 {
			e.WireType = strings.ToUpper(fragments[3])
		}
		e.ParseStatus = "failed"
		e.ParseError = "invalid CSV: " + err.Error()
		return e
	}
	if _, err = r.Read(); err != io.EOF {
		e.ParseStatus = "failed"
		e.ParseError = "multiple CSV records in one syslog message"
		return e
	}
	for i, v := range values {
		e.Fields[fmt.Sprintf("csv_%03d", i)] = v
	}
	if len(values) < 7 {
		e.ParseStatus = "failed"
		e.ParseError = "PAN-OS common header requires at least 7 fields"
		return e
	}
	e.Serial = values[2]
	e.WireType = strings.ToUpper(values[3])
	e.Subtype = values[4]
	if e.Serial == "" {
		fail("missing firewall serial")
	}
	parsedTime := func(v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			t = t.UTC()
			return &t
		}
		for _, layout := range []string{"2006/01/02 15:04:05", "2006/01/02 15:04:05.999999999", "2006-01-02 15:04:05"} {
			if t, err := time.ParseInLocation(layout, v, p.options.Timezone); err == nil {
				e.TimestampTimezone = p.options.Timezone.String() + " (configured assumption)"
				t = t.UTC()
				return &t
			}
		}
		return nil
	}
	e.ReceivedAt = parsedTime(values[1])
	if e.ReceivedAt == nil {
		fail("invalid or missing firewall receive timestamp")
	}
	e.GeneratedAt = parsedTime(values[6])
	if e.GeneratedAt == nil {
		fail("invalid or missing generated timestamp")
	}
	schema, err := p.selectSchema(e.WireType, values)
	if err != nil {
		e.ParseStatus = "unrecognized"
		e.ParseError = err.Error()
		return e
	}
	e.SchemaID = schema.ID
	e.SchemaVersion = schema.ID
	e.LogType = category(e.WireType, e.Subtype, "")
	if len(values) < schema.MinimumFields {
		fail(fmt.Sprintf("%s core needs at least %d fields; received %d", e.WireType, schema.MinimumFields, len(values)))
	}
	max := 6
	for name, index := range schema.Fields {
		if index > max {
			max = index
		}
		if index < len(values) {
			e.Fields[name] = values[index]
		}
	}
	if max+1 < len(values) {
		e.ExtraFields = append(e.ExtraFields, values[max+1:]...)
	}
	f := func(k string) string { return e.Fields[k] }
	e.VSYS = f("vsys")
	if f("device_name") != "" {
		e.DeviceName = f("device_name")
	}
	e.App = f("app")
	e.Action = f("action")
	e.Rule = f("rule")
	e.SrcUser = f("src_user")
	e.DstUser = f("dst_user")
	e.SrcZone = f("src_zone")
	e.DstZone = f("dst_zone")
	e.SessionEndReason = f("session_end_reason")
	e.Severity = f("severity")
	e.Description = f("description")
	ip := func(k string) string {
		v := f(k)
		if v == "" {
			return ""
		}
		addr, err := netip.ParseAddr(v)
		if err != nil {
			fail("invalid " + k)
			return ""
		}
		return addr.String()
	}
	if e.WireType == "CONFIG" {
		if addr, err := netip.ParseAddr(f("src_ip")); err == nil {
			e.SrcIP = addr.String()
		}
	} else {
		e.SrcIP = ip("src_ip")
	}
	if e.WireType == "HIP-MATCH" && e.SrcIP == "" {
		e.SrcIP = ip("src_ipv6")
	}
	e.DstIP = ip("dst_ip")
	e.NATSrcIP = ip("nat_src_ip")
	e.NATDstIP = ip("nat_dst_ip")
	if e.WireType == "GLOBALPROTECT" && e.SrcIP == "" {
		e.SrcIP = ip("public_ipv6")
	}
	num := func(k string, bits int) uint64 {
		v := f(k)
		if v == "" {
			return 0
		}
		n, err := strconv.ParseUint(v, 10, bits)
		if err != nil {
			fail("invalid " + k)
			return 0
		}
		return n
	}
	e.SrcPort = uint16(num("src_port", 16))
	e.DstPort = uint16(num("dst_port", 16))
	e.Bytes = num("bytes", 64)
	e.BytesSent = num("bytes_sent", 64)
	e.BytesReceived = num("bytes_received", 64)
	e.Packets = num("packets", 64)
	e.SessionID = num("session_id", 64)
	if high := f("high_resolution_timestamp"); high != "" {
		if t, err := time.Parse(time.RFC3339Nano, high); err == nil {
			t = t.UTC()
			e.ReceivedAt = &t
		} else {
			fail("invalid high resolution timestamp")
		}
	}
	e.LogType = category(e.WireType, e.Subtype, f("threat_category"))
	return e
}

func (p *Parser) selectSchema(wire string, values []string) (Schema, error) {
	if p.options.SchemaID != "" {
		for _, s := range registry {
			if s.ID == p.options.SchemaID && s.WireType == wire {
				return s, nil
			}
		}
		return Schema{}, fmt.Errorf("configured schema %q does not match wire type %q", p.options.SchemaID, wire)
	}
	if wire == "CONFIG" {
		anchor := func(seq, flags int) bool {
			if flags >= len(values) {
				return false
			}
			if _, err := strconv.ParseUint(values[seq], 10, 64); err != nil {
				return false
			}
			return strings.HasPrefix(values[flags], "0x")
		}
		standard, details := anchor(14, 15), anchor(16, 17)
		if standard == details {
			return Schema{}, fmt.Errorf("ambiguous CONFIG layout: configure a verified schema_id for this sender")
		}
		id := "panos-config-default-v1"
		if details {
			id = "panos-config-details-v1"
		}
		for _, s := range registry {
			if s.ID == id {
				return s, nil
			}
		}
	}
	for _, s := range registry {
		if s.WireType == wire {
			return s, nil
		}
	}
	return Schema{}, fmt.Errorf("unsupported PAN-OS wire type %q; original message retained", wire)
}

func category(wire, subtype, threatCategory string) string {
	switch wire {
	case "THREAT":
		switch strings.ToLower(subtype) {
		case "url":
			return "url"
		case "wildfire":
			return "wildfire"
		case "data", "file", "dlp":
			return "data"
		}
		// PAN-OS uses dns-* for request analysis and adns-* for Advanced
		// DNS Security response analysis. Both retain the THREAT wire family.
		dnsCategory := strings.ToLower(threatCategory)
		if strings.HasPrefix(dnsCategory, "dns-") || strings.HasPrefix(dnsCategory, "adns-") {
			return "dns"
		}
		return "threat"
	case "CONFIG":
		return "configuration"
	case "USERID":
		return "userid"
	case "AUTHENTICATION":
		return "authentication"
	case "HIP-MATCH":
		return "hip"
	default:
		return strings.ToLower(wire)
	}
}

// envelope handles RFC 3164 and RFC 5424 independently from the CSV body.
func envelope(raw string) (body, hostname string, err error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "<") {
		return s, "", nil
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return "", "", fmt.Errorf("invalid syslog priority")
	}
	pri, e := strconv.Atoi(s[1:end])
	if e != nil || pri < 0 || pri > 191 {
		return "", "", fmt.Errorf("invalid syslog priority")
	}
	s = s[end+1:]
	if strings.HasPrefix(s, "1 ") {
		parts := strings.SplitN(s, " ", 7)
		if len(parts) != 7 {
			return "", "", fmt.Errorf("incomplete RFC 5424 header")
		}
		hostname = parts[2]
		s = parts[6]
		if strings.HasPrefix(s, "-") {
			if len(s) == 1 {
				return "", hostname, nil
			}
			if s[1] != ' ' {
				return "", hostname, fmt.Errorf("invalid RFC 5424 structured data")
			}
			s = s[2:]
		} else {
			for strings.HasPrefix(s, "[") {
				quoted, escaped, closed := false, false, false
				for i := 1; i < len(s); i++ {
					c := s[i]
					if escaped {
						escaped = false
						continue
					}
					if c == '\\' && quoted {
						escaped = true
						continue
					}
					if c == '"' {
						quoted = !quoted
					}
					if c == ']' && !quoted {
						s = s[i+1:]
						closed = true
						break
					}
				}
				if !closed {
					return "", hostname, fmt.Errorf("unterminated RFC 5424 structured data")
				}
			}
			if !strings.HasPrefix(s, " ") {
				return "", hostname, fmt.Errorf("missing RFC 5424 message separator")
			}
			s = s[1:]
		}
		if hostname == "-" {
			hostname = ""
		}
		return strings.TrimPrefix(s, "\ufeff"), hostname, nil
	}
	if len(s) < 16 {
		return "", "", fmt.Errorf("incomplete BSD syslog header")
	}
	if _, e := time.Parse("Jan _2 15:04:05", s[:15]); e != nil {
		return "", "", fmt.Errorf("invalid BSD syslog timestamp")
	}
	s = strings.TrimLeft(s[15:], " ")
	sep := strings.IndexByte(s, ' ')
	if sep < 0 {
		return "", "", fmt.Errorf("missing BSD hostname/message separator")
	}
	hostname = s[:sep]
	s = strings.TrimLeft(s[sep+1:], " ")
	// A relay may include a conventional TAG before the native CSV message.
	if colon := strings.Index(s, ": "); colon >= 0 && colon < 64 && !strings.Contains(s[:colon], ",") {
		s = s[colon+2:]
	}
	return s, hostname, nil
}
