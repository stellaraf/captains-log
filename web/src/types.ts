export interface Config {
  auth: { url: string; realm: string; client_id: string };
  version: string;
}
export interface User {
  id: string;
  name: string;
  role: "ADMINISTRATOR" | "ANALYST" | "VIEWER";
}
export type EventRecord = Record<string, string | number | null> & {
  id: string;
  received_at: string;
  log_type: string;
  raw: string;
  src_ip: string;
  dst_ip: string;
};
export interface Field {
  alias: string;
  column: string;
  label: string;
  type: string;
  operators: string[];
}
export interface SavedFilter {
  id?: string;
  name: string;
  description: string;
  query: string;
  log_type: string;
  columns: string[];
  time_range: string;
  sort: string;
  order?: "asc" | "desc";
  favorite: boolean;
  builtin?: boolean;
}
export interface Layout {
  columns: string[];
  widths: Record<string, number>;
  sort: string;
  order: "asc" | "desc";
}
export interface Stats {
  messages_received: number;
  messages_parsed: number;
  parse_failures: number;
  events_inserted: number;
  queue_depth: number;
  spool_bytes: number;
  messages_dropped: number;
  events_per_second: number;
  bytes_per_second: number;
  last_event_received: string;
  listeners: unknown[];
}
export interface Firewall {
  serial: string;
  device_name: string;
  sender_ip: string;
  friendly_name: string;
  site: string;
  tags: string[];
  notes: string;
  panos_version: string;
  first_seen: string;
  last_seen: string;
  events_today: number;
  current_eps: number | null;
  average_eps: number | null;
  peak_eps: number | null;
  rate_windows?: {
    as_of: string;
    timestamp_source: "ingested_at";
    source: "retained_events";
    observation_continuity: "not_verified";
    historical_retention_changes: "not_verified";
    minimum_configured_retention_days: number;
    observed_since: string | null;
    averages: Record<string, { eps: number | null; retained_events: number; from: string; to: string; seconds: number; history_covers_window: boolean; retention_covers_window: boolean; quality: string }>;
    peaks: Record<string, { eps: number | null; bucket_seconds: number; lookback_seconds: number; from: string; to: string; alignment: string; history_covers_window: boolean; retention_covers_window: boolean; quality: string }>;
  };
  status: string;
}
export interface Storage {
  capacity_bytes: number;
  used_bytes: number;
  available_bytes: number;
  database_bytes: number;
  events: number;
  bytes_per_event: number | null;
  daily_growth_bytes: number | null;
  estimated_retention_days: number | null;
  reserve_percent: number;
  requirements: unknown[];
  status: string;
  [key: string]: unknown;
}
export interface ExportJob {
  id: string;
  status: string;
  rows?: number;
  bytes?: number;
  error?: string;
}
export interface DNSResult {
  hostname: string;
  status: string;
}
export const families = [
  ["traffic", "Traffic"],
  ["threat", "Threat"],
  ["url", "URL Filtering"],
  ["wildfire", "WildFire Submissions"],
  ["dns", "DNS Security"],
  ["data", "Data Filtering"],
  ["hip", "HIP Match"],
  ["globalprotect", "GlobalProtect"],
  ["iptag", "IP-Tag"],
  ["userid", "User-ID"],
  ["decryption", "Decryption"],
  ["tunnel", "Tunnel Inspection"],
  ["configuration", "Configuration"],
  ["system", "System"],
  ["alarms", "System alerts"],
  ["authentication", "Authentication"],
  ["unified", "Unified"],
] as const;
export const columns: Record<string, string> = {
  received_at: "Receive Time",
  log_type: "Type",
  src_zone: "From Zone",
  dst_zone: "To Zone",
  src_ip: "Source",
  src_hostname: "Source Hostname",
  src_user: "Source User",
  dst_ip: "Destination",
  dst_hostname: "Destination Hostname",
  src_port: "Source Port",
  dst_port: "Destination Port",
  app: "Application",
  previous_app: "Previous Application",
  action: "Action",
  rule: "Rule",
  session_end_reason: "Session End Reason",
  bytes: "Bytes",
  bytes_sent: "Bytes Sent",
  bytes_received: "Bytes Received",
  packets: "Packets",
  session_id: "Session ID",
  nat_src_ip: "NAT Source",
  nat_dst_ip: "NAT Destination",
  device_name: "Device",
  serial: "Serial",
  vsys: "VSYS",
  subtype: "Subtype",
  severity: "Severity",
  description: "Description",
  generated_at: "Generated Time",
  ingested_at: "Ingested Time",
  sender_ip: "Sender",
  schema_version: "Schema",
  parser_version: "Parser",
  schema_id: "Schema ID",
  timestamp_timezone: "Timestamp Timezone",
  panos_version: "PAN-OS Version",
  wire_type: "Wire Type",
  parse_status: "Parse Status",
  parse_error: "Parse Error",
  raw: "Raw Message",
};
export function defaultLayout(type: string): Layout {
  const defaults: Record<string, string[]> = {
    traffic: [
      "received_at",
      "log_type",
      "src_zone",
      "dst_zone",
      "src_ip",
      "src_hostname",
      "src_user",
      "dst_ip",
      "dst_hostname",
      "src_port",
      "dst_port",
      "app",
      "previous_app",
      "action",
      "rule",
      "session_end_reason",
      "bytes",
      "bytes_sent",
      "bytes_received",
      "packets",
      "session_id",
      "nat_src_ip",
      "nat_dst_ip",
      "device_name",
      "vsys",
    ],
    parsing: [
      "received_at",
      "sender_ip",
      "serial",
      "log_type",
      "parse_status",
      "parse_error",
    ],
    system: [
      "received_at",
      "subtype",
      "severity",
      "description",
      "device_name",
      "serial",
      "vsys",
    ],
    alarms: [
      "received_at",
      "subtype",
      "severity",
      "description",
      "device_name",
      "serial",
      "vsys",
    ],
    configuration: [
      "received_at",
      "src_user",
      "src_ip",
      "action",
      "description",
      "device_name",
      "serial",
    ],
    authentication: [
      "received_at",
      "src_user",
      "src_ip",
      "dst_ip",
      "action",
      "description",
      "device_name",
      "vsys",
    ],
  };
  return {
    columns: defaults[type] || [
      "received_at",
      "log_type",
      "subtype",
      "src_ip",
      "dst_ip",
      "app",
      "action",
      "severity",
      "description",
      "device_name",
    ],
    widths: {
      received_at: 178,
      src_ip: 146,
      dst_ip: 146,
      rule: 180,
      description: 320,
      parse_error: 320,
      src_port: 95,
      dst_port: 95,
      log_type: 90,
    },
    sort: "received_at",
    order: "desc",
  };
}
