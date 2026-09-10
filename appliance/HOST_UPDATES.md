# Compatible host updates

Captain's Log appliances with an enrolled host generation require a **combined release containing a versioned host bundle**. This also applies when only an OCI application/database image changes. The GitHub poller refuses an OCI-only release before downloading its artifacts, and the local update manager refuses it before any lifecycle hook or selection write. Legacy installations without host enrollment retain the existing OCI update path.

The publisher must include `host.tar` (or another direct, bounded `.tar` filename), alongside OCI artifacts, in the signed `manifest.json`. The host component has exactly these fields:

```json
{
  "artifact": "host.tar",
  "version": "0.1.1",
  "from_versions": ["0.1.0"],
  "rollback_safe": true,
  "abi": 1,
  "host_source_sha256": "<SHA-256 from the verified host bundle>"
}
```

The artifact entry supplies its exact `bytes` and archive `sha256`. The artifact may not also serve another component. Use `appliance/packer/build_host_bundle.py` with the same frozen source manifest used for the release. Always increment the signed release sequence and host version; a new version produces a distinct immutable generation even when code bytes are unchanged. `from_versions` must explicitly include every supported accepted host version, including the actual measured `0.0.0-factory.<source-hash-prefix>` version for supported initial appliance images. Do not replace that value with a wildcard.

The archive is deterministic, bounded USTAR, with a fixed ABI/catalog and per-file source/hash/mode inventory. The archive SHA-256 names its directory under `/usr/lib/nebulalog/generations`. The factory public publisher key, Rocky trust, customer configuration, private keys and logs are outside host generations.

## Transaction and recovery

The existing manager holds its application/OS coordination locks, verifies the signed release, and pins the previously accepted manager/adapters. It stages a fresh immutable generation, then verifies runtime compatibility and captures a private, immutable `host-runtime-plan.json`. The plan binds the release manifest, old/new generations, every package resource's exact old/new bytes and permissions, complete generation additions, selection variants, and hash-only customer/trust inventories.

Preflight requires an authorized AIDE comparison. Only the exact staged generation additions may be new; unrelated drift refuses the update. Backups precede selection and runtime writes. The manager records selection intent before replacing the selected-generation record. Fixed package resources are atomically reconciled only when their current contents match the accepted old or prepared new bytes. A fixed installed boot shim verifies all selected generation bytes before importing project code.

Every update hook remains on the previous coordinator, including health, rollback and finalization. Actual resource files, service state, and isolated selected-generation imports must match the candidate. After the other runtime/security/log-ingestion checks pass, authorized AIDE acceptance must verify the exact change plan, reject unrelated discrepancies, and qualify the new integrity baseline. The manager alone records the new accepted generation and commit. Finalization repeats the required acceptance before releasing maintenance.

An interrupted transaction can restore the previous generation and retained resources without executing candidate hooks. Recovery preserves the rejected sequence, so GitHub polling cannot reactivate a rolled-back release. Damaged candidate archives do not prevent selecting/restoring prior code; independent integrity acceptance can still keep maintenance active if any remaining filesystem damage is unqualified. A failed finalization preserves committed state and requires verification/finalization, rather than silently reversing accepted databases.

## ABI 1 resource treatment

| Catalog content | Compatible update behavior |
| --- | --- |
| Manager and adapter Python modules | Selected as one complete immutable generation through the fixed boot shim; isolated import provenance is checked. |
| Fixed systemd units/drop-in | Prior package bytes required; protected backup, atomic replacement, daemon reload, and measured service checks. |
| Container and HTTPS templates | Shared package templates update; live files are rendered using retained or signed image pins and the existing configured HTTPS identity. Local changes refuse automatic replacement. |
| Fixed command wrappers | Must remain byte-identical; changes require a qualified dispatcher migration. |
| Security/default policy files | Must remain byte-identical, including AIDE policy/default config, storage and dracut policy; changes require a qualified policy/boot migration. |
| Container network definition | Must remain byte-identical; network migrations require separate qualification. |
| Keycloak realm template | Must remain byte-identical; identity/schema migrations require separate qualification. |
| Customer settings, certificates, trust and secrets | Hash-checked preservation; no replacement from downloaded host archives. |

An unsupported resource change reports the precise catalog path and refuses before backup or selection. The private staged `host-refusal.json` receipt contains only schema, the fixed `qualified_migration_required` reason, catalog resource path, sequence and manifest hash. The manager copies that validated schema into `transaction.host_refusal`; it never publishes raw adapter exceptions or configuration contents. The immutable plan and retained backups remain private on encrypted manager storage. No manifest field can select a command, executable hook or destination outside the fixed catalog.

## Qualification status

Source integration and isolated filesystem/transaction tests are distinct from native guest acceptance. Fixture service, AIDE and import-probe responses do not qualify real appliance updates. Before publishing a stable release, require real Rocky x86_64 evidence for the combined host+OCI update, new-code provenance, authorized AIDE transition, TLS/log ingestion, rollback, interrupted writes, boot recovery, and finalization failure. OS RPM maintenance requires its own qualified authorized-baseline transition; the host component plan does not authorize arbitrary OS/package drift.
