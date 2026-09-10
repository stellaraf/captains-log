package panos

// Schema is a versioned field-layout definition, not an inferred software release.
// MinimumFields validates the core; extension fields may be absent or appended.
type Schema struct {
	ID            string         `json:"id"`
	WireType      string         `json:"wire_type"`
	Revision      string         `json:"revision"`
	SourceURL     string         `json:"source_url"`
	MinimumFields int            `json:"minimum_fields"`
	Fields        map[string]int `json:"fields"`
}

const reference = "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/"

func networkFields() map[string]int {
	return map[string]int{
		"src_ip": 7, "dst_ip": 8, "nat_src_ip": 9, "nat_dst_ip": 10, "rule": 11, "src_user": 12, "dst_user": 13, "app": 14, "vsys": 15, "src_zone": 16, "dst_zone": 17, "inbound_interface": 18, "outbound_interface": 19, "log_forwarding_profile": 20, "session_id": 22, "repeat_count": 23, "src_port": 24, "dst_port": 25, "nat_src_port": 26, "nat_dst_port": 27, "flags": 28, "protocol": 29, "action": 30,
	}
}
func fieldsWith(base map[string]int, extension map[string]int) map[string]int {
	for k, v := range extension {
		base[k] = v
	}
	return base
}

var registry = []Schema{
	{"panos-hipmatch-v1", "HIP-MATCH", "2026-09-07", reference + "hip-match-log-fields", 15, map[string]int{"src_user": 7, "vsys": 8, "machine_name": 9, "os": 10, "src_ip": 11, "description": 12, "repeat_count": 13, "hip_type": 14, "sequence": 17, "action_flags": 18, "vsys_name": 23, "device_name": 24, "src_ipv6": 26, "host_id": 27, "client_serial": 28, "mac_address": 29, "high_resolution_timestamp": 30}},
	{"panos-iptag-v1", "IPTAG", "2026-09-07", reference + "ip-tag-log-fields", 11, map[string]int{"vsys": 7, "src_ip": 8, "description": 9, "event_id": 10, "repeat_count": 11, "timeout": 12, "data_source_name": 13, "data_source_type": 14, "data_source_subtype": 15, "sequence": 16, "action_flags": 17, "vsys_name": 22, "device_name": 23, "high_resolution_timestamp": 25}},
	{"panos-decryption-v1", "DECRYPTION", "2026-09-07", reference + "decryption-log-fields", 31, fieldsWith(networkFields(), map[string]int{"config_version": 5, "tunnel": 31, "rule_uuid": 36, "client_handshake_stage": 37, "server_handshake_stage": 38, "tls_version": 39, "key_exchange": 40, "encryption_algorithm": 41, "hash_algorithm": 42, "policy_name": 43, "elliptic_curve": 44, "root_status": 46, "chain_status": 47, "proxy_type": 48, "certificate_serial": 49, "fingerprint": 50, "subject_common_name": 60, "issuer_common_name": 61, "root_common_name": 62, "sni": 63, "description": 64, "high_resolution_timestamp": 72, "source_hostname": 79, "destination_hostname": 87, "sequence": 89, "action_flags": 90, "vsys_name": 95, "device_name": 96})},

	{"panos-traffic-core-v1", "TRAFFIC", "2026-09-07", reference + "traffic-log-fields", 35, fieldsWith(networkFields(), map[string]int{"bytes": 31, "bytes_sent": 32, "bytes_received": 33, "packets": 34, "start_time": 35, "elapsed": 36, "category": 37, "sequence": 39, "action_flags": 40, "source_country": 41, "destination_country": 42, "packets_sent": 44, "packets_received": 45, "session_end_reason": 46, "vsys_name": 51, "device_name": 52, "rule_uuid": 65, "source_hostname": 82, "destination_hostname": 90, "high_resolution_timestamp": 102})},
	{"panos-threat-core-v1", "THREAT", "2026-09-07", reference + "threat-log-fields", 35, fieldsWith(networkFields(), map[string]int{"description": 31, "threat_id": 32, "category": 33, "severity": 34, "direction": 35, "sequence": 36, "action_flags": 37, "source_country": 38, "destination_country": 39, "content_type": 41, "file_digest": 43, "file_type": 47, "vsys_name": 58, "device_name": 59, "threat_category": 69, "content_version": 70, "rule_uuid": 76, "source_hostname": 86, "destination_hostname": 94, "high_resolution_timestamp": 107})},
	{"panos-system-v1", "SYSTEM", "2026-09-07", reference + "system-log-fields", 15, map[string]int{"vsys": 7, "event_id": 8, "object": 9, "module": 12, "severity": 13, "description": 14, "sequence": 15, "action_flags": 16, "vsys_name": 21, "device_name": 22, "high_resolution_timestamp": 25}},
	{"panos-config-default-v1", "CONFIG", "2026-09-07", reference + "config-log-fields", 14, map[string]int{"src_ip": 7, "vsys": 8, "action": 9, "src_user": 10, "client": 11, "result": 12, "description": 13, "sequence": 14, "action_flags": 15, "vsys_name": 20, "device_name": 21, "device_group": 22, "audit_comment": 23, "high_resolution_timestamp": 25}},
	{"panos-config-details-v1", "CONFIG", "2026-09-07", reference + "config-log-fields", 18, map[string]int{"src_ip": 7, "vsys": 8, "action": 9, "src_user": 10, "client": 11, "result": 12, "description": 13, "before_change": 14, "after_change": 15, "sequence": 16, "action_flags": 17, "vsys_name": 22, "device_name": 23, "device_group": 24, "audit_comment": 25, "high_resolution_timestamp": 27}},
	{"panos-authentication-v1", "AUTHENTICATION", "2026-09-07", reference + "authentication-log-fields", 21, map[string]int{"vsys": 7, "src_ip": 8, "src_user": 9, "normalized_user": 10, "object": 11, "rule": 12, "repeat_count": 13, "authentication_id": 14, "vendor": 15, "log_forwarding_profile": 16, "server_profile": 17, "description": 18, "client_type": 19, "action": 20, "factor_number": 21, "sequence": 22, "action_flags": 23, "vsys_name": 28, "device_name": 29, "authentication_protocol": 31, "rule_uuid": 32, "high_resolution_timestamp": 33, "source_hostname": 40}},
	{"panos-userid-v1", "USERID", "2026-09-07", reference + "user-id-log-fields", 12, map[string]int{"vsys": 7, "src_ip": 8, "src_user": 9, "data_source_name": 10, "event_id": 11, "repeat_count": 12, "timeout": 13, "src_port": 14, "dst_port": 15, "data_source": 16, "data_source_type": 17, "sequence": 18, "action_flags": 19, "vsys_name": 24, "device_name": 25, "high_resolution_timestamp": 33}},
	{"panos-globalprotect-v1", "GLOBALPROTECT", "2026-09-07", reference + "globalprotect-log-fields", 29, map[string]int{"vsys": 7, "event_id": 8, "stage": 9, "authentication_method": 10, "tunnel_type": 11, "src_user": 12, "source_region": 13, "machine_name": 14, "src_ip": 15, "public_ipv6": 16, "private_ip": 17, "private_ipv6": 18, "host_id": 19, "client_serial": 20, "client_version": 21, "client_os": 22, "client_os_version": 23, "repeat_count": 24, "reason": 25, "error": 26, "description": 27, "action": 28, "location": 29, "duration": 30, "connect_method": 31, "error_code": 32, "portal": 33, "sequence": 34, "action_flags": 35, "high_resolution_timestamp": 36, "gateway": 41, "vsys_name": 46, "device_name": 47}},
}

// Schemas returns defensive copies, safe for diagnostics and schema discovery.
func Schemas() []Schema {
	result := make([]Schema, len(registry))
	for i, s := range registry {
		result[i] = s
		result[i].Fields = map[string]int{}
		for k, v := range s.Fields {
			result[i].Fields[k] = v
		}
	}
	return result
}
