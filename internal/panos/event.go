// Package panos parses standard Palo Alto Networks PAN-OS syslog messages.
package panos

import "time"

const ParserVersion = "0.1.0"

// Event separates raw evidence and parser provenance from normalized search fields.
// Missing generated/receive timestamps are nil; IngestedAt is always local receipt.
type Event struct {
	ID                string            `json:"id"`
	IngestedAt        time.Time         `json:"ingested_at"`
	GeneratedAt       *time.Time        `json:"generated_at"`
	ReceivedAt        *time.Time        `json:"received_at"`
	SenderIP          string            `json:"sender_ip"`
	Serial            string            `json:"serial"`
	DeviceName        string            `json:"device_name"`
	VSYS              string            `json:"vsys"`
	LogType           string            `json:"log_type"`
	WireType          string            `json:"wire_type"`
	Subtype           string            `json:"subtype"`
	SchemaVersion     string            `json:"schema_version"`
	SchemaID          string            `json:"schema_id"`
	PANOSVersion      string            `json:"panos_version"`
	ParserVersion     string            `json:"parser_version"`
	TimestampTimezone string            `json:"timestamp_timezone"`
	ParseStatus       string            `json:"parse_status"`
	ParseError        string            `json:"parse_error"`
	Raw               string            `json:"raw"`
	RawBase64         string            `json:"raw_base64,omitempty"`
	SrcIP             string            `json:"src_ip"`
	DstIP             string            `json:"dst_ip"`
	SrcPort           uint16            `json:"src_port"`
	DstPort           uint16            `json:"dst_port"`
	SrcZone           string            `json:"src_zone"`
	DstZone           string            `json:"dst_zone"`
	SrcUser           string            `json:"src_user"`
	DstUser           string            `json:"dst_user"`
	App               string            `json:"app"`
	PreviousApp       string            `json:"previous_app"`
	Action            string            `json:"action"`
	Rule              string            `json:"rule"`
	SessionEndReason  string            `json:"session_end_reason"`
	Bytes             uint64            `json:"bytes"`
	BytesSent         uint64            `json:"bytes_sent"`
	BytesReceived     uint64            `json:"bytes_received"`
	Packets           uint64            `json:"packets"`
	SessionID         uint64            `json:"session_id"`
	NATSrcIP          string            `json:"nat_src_ip"`
	NATDstIP          string            `json:"nat_dst_ip"`
	Severity          string            `json:"severity"`
	Description       string            `json:"description"`
	Fields            map[string]string `json:"fields"`
	ExtraFields       []string          `json:"extra_fields"`
}

type Options struct {
	Timezone     *time.Location
	PANOSVersion string
	// SchemaID forces a registry layout when a sender uses an ambiguous format.
	SchemaID string
}

type Parser struct{ options Options }

func NewParser(options Options) *Parser {
	if options.Timezone == nil {
		options.Timezone = time.UTC
	}
	return &Parser{options: options}
}
func Parse(raw []byte, sender string, ingestedAt time.Time) Event {
	return NewParser(Options{}).Parse(raw, sender, ingestedAt)
}
