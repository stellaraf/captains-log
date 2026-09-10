# Parser fixtures

`traffic.log`, `url.log`, `system.log`, and configuration fixtures are constructed standard-format examples based on the official field references.

`pa1410-12.1-traffic.log` and `pa1410-12.1-dns.log` derive their field count/order and native family/subtype from actual PA-1410 PAN-OS 12.1.4-h8 Syslog captures. The native layouts contain 130 and 140 fields, respectively. **Every customer-identifying value was replaced or cleared**, including all original timestamps, addresses, usernames, rule names, serials, interfaces, URLs, threat identifiers, hostnames, UUIDs, and unknown trailing fields. Public protocol/application/action/subtype/category tokens remain to preserve interpretation. Counts, ports, session IDs, and other numerical values are fixed test data. Original captures are not in this repository.

Tests assert addresses, ports, application, action, subtype/category, timestamps and offsets, byte/packet counters, and extension tolerance. Separate private validation compared actual stored values against matching firewall XML API log sequences. See `docs/validation/PALO_REAL.md`.
