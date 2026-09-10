# Offline appliance image bundle

The appliance can initialize without contacting a container registry. Its installed bundle contains the four release-selected Linux/amd64 images: Captain’s Log, PostgreSQL, ClickHouse and the qualified Keycloak FIPS image. Each reference names the exact platform image manifest by SHA-256. A multi-platform index digest, Docker image ID, mutable tag or newly recompressed manifest is not interchangeable with that digest.

The bundle is release input, not proof of publisher authenticity. Its manifest and archives must be covered by the trusted appliance release/build verification. SHA-256 checks detect changed bytes; an attacker able to replace both unsigned hashes and archives has not been excluded merely by matching them.

## Installed layout and contract

```text
/usr/share/nebulalog/images/
  manifest.json
  nebulalog.oci.tar
  postgresql.oci.tar
  clickhouse.oci.tar
  keycloak-fips.oci.tar
/etc/nebulalog/images.json
```

`images.json` maps exactly `NEBULALOG_IMAGE`, `POSTGRESQL_IMAGE`, `CLICKHOUSE_IMAGE` and `KEYCLOAK_FIPS_IMAGE` to immutable `repository@sha256:<64hex>` references. The bundle manifest has exactly `schema` and `images`:

```json
{
  "schema": 1,
  "images": {
    "NEBULALOG_IMAGE": {
      "archive": "nebulalog.oci.tar",
      "sha256": "archive-file-sha256-as-64-lowercase-hex-characters",
      "reference": "registry.example/nebulalog@sha256:exact-amd64-child-manifest-digest"
    },
    "POSTGRESQL_IMAGE": {"archive": "postgresql.oci.tar", "sha256": "...", "reference": "..."},
    "CLICKHOUSE_IMAGE": {"archive": "clickhouse.oci.tar", "sha256": "...", "reference": "..."},
    "KEYCLOAK_FIPS_IMAGE": {"archive": "keycloak-fips.oci.tar", "sha256": "...", "reference": "..."}
  }
}
```

The placeholders above are illustrative. The builder emits actual digests. Archives, manifest and pin file must be root-owned regular files without group/world write permission in the installed guest. Archive names are unique basenames ending in `.oci.tar`; paths, links and arbitrary components are rejected.

## Build from local Docker images

Create an input JSON map with exactly the four image keys. Each entry contains a local Docker `source` and its independently selected platform manifest `reference`:

```json
{
  "NEBULALOG_IMAGE": {"source": "nebulalog/appliance-app:candidate", "reference": "docker.io/nebulalog/appliance-app@sha256:<actual-digest>"},
  "POSTGRESQL_IMAGE": {"source": "postgres:qualified-version", "reference": "docker.io/library/postgres@sha256:<actual-digest>"},
  "CLICKHOUSE_IMAGE": {"source": "clickhouse/clickhouse-server:qualified-version", "reference": "docker.io/clickhouse/clickhouse-server@sha256:<actual-digest>"},
  "KEYCLOAK_FIPS_IMAGE": {"source": "nebulalog/keycloak-fips:qualified-version", "reference": "docker.io/nebulalog/keycloak-fips@sha256:<actual-digest>"}
}
```

Run:

```sh
python3 appliance/packer/bundle_images.py --input /build/image-sources.json --output /build/new-image-bundle
```

The helper uses `docker image save --platform=linux/amd64` with argv arguments and streams output under a size/time budget. It never pulls a missing image. The local Docker image store must support OCI-format export preserving the chosen manifest; a classic Docker archive without `oci-layout` and `index.json` is refused.

An entry may instead contain `archive: "/build/existing-image.oci.tar"` and `reference`. The default copies and verifies it. Add `--reuse-existing-archives` to explicitly hard-link existing verified archives on the same filesystem and avoid duplicate allocation. Reused sources must remain immutable; changing either hard-link name changes the underlying bytes. Installer, seal and loader verification detect subsequent changes.

The destination must not exist. All files are created in a private staging directory, fully verified, and then published by directory rename. Failures remove only this newly created staging directory and preserve source files. The result includes the four archives, `manifest.json` and `images.json`; install the pin file at `/etc/nebulalog/images.json`.

Limits are 8 GiB per archive, 24 GiB for the bundle, 100,000 archive entries, 4 MiB per JSON metadata object and 1,024 image layers. The export budget additionally reserves 2 GiB of scratch space. These are rejection limits, not capacity or throughput claims.

## Verify without loading or executing anything

The installer and sealing process can call the pure verifier before encrypted runtime storage exists:

```python
from pathlib import Path
from nebulalog_manager.image_bundle import strict_json, verify_bundle

pins = strict_json(Path("/etc/nebulalog/images.json").read_bytes())
evidence = verify_bundle(Path("/usr/share/nebulalog/images"), pins, root_owned=True)
```

This performs no subprocess, registry, Podman, extraction or firstboot operation. For a non-root development staging directory, omit `root_owned=True`; installed guest verification must require it.

Verification checks the whole archive SHA-256, bounded tar headers, unique safe file paths, single-image OCI layout/index, selected manifest digest, each stored blob's SHA-256, all referenced descriptor sizes, local config/layers, Linux/amd64 configuration and root-filesystem layer metadata. Links, devices, FIFOs, extended tar headers, external blob URLs, duplicate JSON properties, duplicate paths, missing blobs and changed-in-place files are refused. Layer tar payloads are hashed as image blobs; this verifier does not unpack or execute their contents.

## Load after firstboot storage enrollment

`/usr/libexec/nebulalog/load-image-bundle` accepts no arguments. It first requires the actual firstboot host/storage gate, including the identity-bound LUKS/XFS mount and measured FIPS/SELinux/firewall/audit controls. It then verifies:

- Podman's graphroot is `/var/lib/nebulalog/containers`.
- Image storage and `/var/lib/nebulalog/tmp` share the enrolled XFS mount.
- The extraction temporary directory is root-owned mode `0700`.
- All four archives and references pass complete preflight before copying any image.
- Encrypted free space exceeds four times the aggregate archive size plus 1 GiB. Actual image unpacking still has to succeed; compressed size is not a guaranteed upper bound on runtime allocation.

Skopeo inspection and copy use only local transports:

```text
skopeo --override-os linux --override-arch amd64 inspect oci-archive:<installed-archive>
skopeo --override-os linux --override-arch amd64 copy --preserve-digests oci-archive:<installed-archive> containers-storage:<exact-repository@sha256-digest>
```

Each subprocess gets `TMPDIR=/var/lib/nebulalog/tmp`; the parent process environment is unchanged. No registry transport or fallback is used. After each copy, Podman must resolve the exact reference and report the expected manifest digest, config ID, Linux OS and amd64 architecture. An existing matching image is verified and reused. A retry does not replace a mismatched image silently. Receipt: `/var/lib/nebulalog/manager/image-bundle-receipt.json`.

The loader retains the installed system trust policy. It does not supply a permissive Skopeo policy or weaken signature rules to force a copy. Digest preservation and destination digest support follow upstream [Skopeo copy](https://github.com/containers/skopeo/blob/main/docs/skopeo-copy.1.md) and [containers image transports](https://github.com/containers/image/blob/main/docs/containers-transports.5.md).

## Evidence and remaining boundary

The development candidate bundle was built and independently reverified: **955,435,520 bytes**, four Linux/amd64 OCI archives, 45 verified content blobs. The archive/manifest/config digests are retained in `.local/appliance-build/image-bundle-candidate/manifest.json` and `.local/appliance-build/bundle-build.json`.

Nineteen image-bundle tests pass. They cover outer/archive tampering, inner blob tampering, missing blobs, wrong architecture or manifest, unsafe paths/links/FIFO, untrusted ownership, pure verification without processes, safe builder failure, hard-link reuse, storage-gate refusal and digest-preserving command/postcondition behavior. Command-model tests are not proof of a real Rocky Skopeo/Podman load. Actual guest loading, immutable reference resolution and runtime startup remain distinct acceptance evidence.

Package repository trust is separately enrolled from the installer-verified `/etc/nebulalog/trust.json`. Bootstrap checks the actual fixed Rocky 9 key bytes against its SHA-256 and requires the qualified Rocky 9 fingerprint `21CB256AE16FC54C6E652949702D426D350D275D`, published in [Rocky Linux's GPG key information](https://rockylinux.org/resources/gpg-key-info). The digest enters encrypted lifecycle configuration; a subsequent mismatch refuses setup rather than resetting established trust.
