# Captain’s Log appliance components

Host management lives outside the application container. Python standard-library modules invoke fixed Linux tools through argv arrays (never a shell command supplied by a request). Imports and unit tests do not change the host. Privileged operations require Linux root and root-owned configuration; development commands should use the pure planners/tests.

```sh
PYTHONPATH=appliance:appliance/adapters python3 -m unittest discover -s appliance/tests -v
PYTHONPATH=appliance python3 -m nebulalog_manager.cli --help
```

Components:

- `nebulalog_manager/storage.py`: authoritative Linux inspection, persisted identity validation, pure grow plans and guarded grow execution.
- `nebulalog_manager/enrollment.py`: explicit blank-disk review and confirmation, LUKS/PV enrollment, recovery-key creation and pool extension journal.
- `nebulalog_manager/sizing.py`: measured growth forecasts with reserve and uncertainty.
- `nebulalog_manager/security.py`: measured host state and pinned/reviewed OpenSCAP assessments.
- `nebulalog_manager/updates.py`: signed-manifest verification, rollback safety, fixed-adapter transactions and anti-replay high-water marks.
- `nebulalog_manager/update_enrollment.py`: verified offline/runtime initial component identity and explicit immutable publisher-public-key enrollment; [contract and operator instructions](../docs/UPDATE_ENROLLMENT.md).
- `nebulalog_manager/backup.py`: PostgreSQL/configuration archive, CMS authenticated encryption and integrity-checked staged restore.
- `nebulalog_manager/os_updates.py`: maintenance-window OS update/reboot control with required local adapters.
- `packer/`: install-time FIPS Rocky image recipe, offline OVA packaging and digest-pinned Quadlet rendering.
- `systemd/`, `quadlet/`, `security/`: guest deployment recipes and minimum controls.

Production image references must be selected by a signed qualified release, never `latest`. Example render:

```sh
python3 appliance/packer/render_quadlets.py --images <verified-images.json> --output <new-staging-directory>
```

The image JSON has four keys: `NEBULALOG_IMAGE`, `POSTGRESQL_IMAGE`, `CLICKHOUSE_IMAGE`, `KEYCLOAK_FIPS_IMAGE`; every value must be a registry reference ending in `@sha256:<64hex>`. Rendering does not pull images, apply host settings or validate the Podman generator. Run the generator's `--dryrun` inside the exact Rocky/Podman build before promotion.

See [appliance validation](../docs/APPLIANCE_VALIDATION.md) for evidence, [OVA installation](../docs/INSTALL_OVA.md) for build gates and [updates](../docs/UPDATES.md) for lifecycle qualification. Guarded encrypted setup, the local console wizard, runtime provisioning, sanitized host-status bridge and fixed lifecycle adapters are implemented with local test coverage. Final installed-guest enrollment, provider, storage, update/recovery and hypervisor acceptance remain outstanding. Privileged UI-to-host mutations are not implied by the read-only status bridge. No production-ready or certified appliance is claimed.

## Vendor-only patching decision (October 13, 2026)

The appliance retains vendor-supplied Rocky kernels. Automatic OS updates are
enabled by initial setup and evaluated every 15 minutes; transactions run only
in the configured maintenance window. Package signature/repository controls,
backup, host security and runtime checks remain mandatory. Required reboots
follow preparation and unlock checks within that window. This is automatic
vendor patching with controlled reboots, not reboot-free kernel live patching.

On October 13, the 20 OS-update and activation regression tests passed. The
qualification guest's OS-update timer was enabled and active, but its maintenance
policy was absent because firstboot remains blocked by the vendor kernel HKDF
self-test failure. Automatic patch installation and reboot acceptance therefore
remain unverified. No custom kernel repair is selected for release.
