# PAN-OS-style filter language

Use parentheses, `and`, `or`, and prefix `not`. Operators are case-insensitive;
values remain case-sensitive for equality. `contains` performs case-insensitive
substring matching. AND binds more tightly than OR; NOT binds most tightly.

```text
( addr.src in 10.0.0.0/8 ) and ( port.dst eq 443 )
( app eq ssl ) or ( app eq web-browsing )
not ( action eq allow )
( addr.dst in 2001:db8::/32 )
( rule eq "Default Outbound" )
( bytes geq 1048576 )
```

Aliases: `addr.src`, `addr.dst`, `port.src`, `port.dst`, `zone.src`, `zone.dst`,
`user.src`, `user.dst`, `app`, `action`, `rule`, `device` (serial), `device.name`,
`vsys`, `type`, `subtype`, `severity`, `bytes`, `packets`, `session.id`,
`nat.src`, `nat.dst`, `parse.status`. `/api/fields` returns type/operator metadata.

IP fields support `eq`, `neq`, `in`, `not-in`; `in` accepts a single address or
CIDR, IPv4 and IPv6. Ports and counters support `eq`, `neq`, `gt`, `geq`, `lt`,
`leq`; symbolic comparisons and `gte`/`lte` are accepted. Text fields support
`eq`, `neq`, `contains`. Negate a text predicate using `not (...)`.

Quote whitespace-containing values. Within quotes, escape the matching quote or
backslash with a backslash; other backslashes remain literal (including domain
usernames). Filters are capped at 8,192 characters, 1,024 tokens, 32 nesting
levels and 2,048 characters per value. Invalid input returns a character position
before contacting the database. No arbitrary SQL, regex substitution or user
identifiers are accepted. Values use ClickHouse typed parameters.

Graphical and click-to-filter actions generate this same language and invoke the
same validation endpoint. Compatibility is practical, not a claim of complete
PAN-OS grammar coverage. Time and category scopes are additional API predicates.
