# Appliance application image

This recipe builds the API, collector, migrations and web interface from a captured source archive for Linux/amd64. The production host runs the same image as separate API and ingestion services using Podman Quadlets. It is independent of the running Docker development stack.

```sh
python3 appliance/packer/build_application.py \
  --source . \
  --tag nebulalog/appliance-app:local-candidate \
  --receipt .local/appliance-build/application-build.json
python3 appliance/images/application/verify-image.py nebulalog/appliance-app:local-candidate
```

The helper uses `prepare_provenance.source_snapshot` and `application_hash` to select only captured regular files under `cmd/`, `internal/`, `web/` and `migrations/`, plus `go.mod`, `go.sum`, `LICENSE` and this `Containerfile`. It rehashes the exact file bytes while writing a private tar, rejects changed/missing files and symlink ancestors, then supplies the completed tar to `docker build` on stdin. The live workspace is never a Docker context. Uncaptured/ignored files and unrelated host source cannot enter through `COPY web/`; known credential files and generated output are refused if they appear in the captured selection. No `.dockerignore`, SSH agent or build-secret option is injected.

The archive is deterministic: sorted regular files, mode `0644`, UID/GID zero, empty owner names and timestamp zero. Parent directories are implicit. Local executable bits and modification times are not build inputs. Limits are 20,000 files, 128 MiB per file and 512 MiB for the complete context; exceeding a limit stops before Docker. The helper allows only an explicit local `nebulalog/name:tag`, fixes Linux/amd64, computes `APPLICATION_SOURCE_SHA256` internally and does not expose arbitrary build arguments. Optional `--version` defaults to `0.2.0-appliance-candidate` and accepts only a bounded semantic version. It controls the binary's build version; the Containerfile's descriptive OCI version label remains its recipe default.

Docker's `--iidfile` identifies the image actually built. The helper inspects that immutable ID, verifies its Linux/amd64 platform and source label, then atomically writes a new mode-`0600` receipt containing the image ID, source hash/file map, base commit/dirty state, normalized context hash/size and requested version. Existing receipts are never overwritten. It performs no `docker run`, push or image deletion. A failed build/inspection publishes no success receipt and leaves existing evidence intact. Temporary context files are removed on either outcome. Use the receipt's `local_image_id` for subsequent verification/export if a local tag could have changed.

The required source hash is stored in the immutable OCI configuration. Initial release enrollment compares it to the source manifest; a current source snapshot cannot qualify an older application image. Capture final appliance provenance after application edits finish and ensure its application hash still matches the build receipt. This provenance is not a publisher signature. Base-image/dependency downloads during the build remain governed by the pinned recipe; a tar context does not make the build offline or independently reproducible.

The verifier runs the actual local image without network access, credentials, writable root, mounted data or capabilities. It checks the runtime identity, frozen Go module metadata, positive FIPS startup and refusal when FIPS mode is disabled or policy is malformed. It does not establish guest service health or cryptographic operating-environment qualification.

## Build inputs and cryptographic boundary

| Input | Pinned input |
|---|---|
| Go builder | Go 1.27.2, amd64 manifest `55395706e9703db746cc507abfc4eb2aea75918f8a8024e4848e2cb81004f5ad` |
| Go cryptographic module | `GOFIPS140=v1.0.0`, build reports `v1.0.0-c2097c7c` |
| Web builder | Node 24 bookworm-slim, amd64 manifest `6642ef280aebc09c4541bee0b15c9f89f0f3f3c247ddee79ae1d37eddfdcbbaa` |
| Runtime | RESF Rocky Linux 9.8, amd64 manifest `ed654c694190a670bb5c33f68995b862214fc96ffbdca95e07a8935ba0a3717d` |
| Go dependencies | Exact `go.mod` and `go.sum`; recorded in `/opt/nebulalog/go-build-info.txt` |
| Web dependencies | Exact `web/package-lock.json`; `npm ci` |
| Runtime RPM inventory | `/opt/nebulalog/rpm-bom.tsv`, including package license fields |
| Application license | AGPL-3.0-only, `/opt/nebulalog/LICENSE`; dependencies retain their own licenses |

The runtime binary is built with `CGO_ENABLED=0`, so its TLS and application cryptography use the selected Go module rather than the runtime system OpenSSL library. The kernel FIPS flag alone does not enable Go FIPS mode. The application independently requires `crypto/fips140.Enabled()` before handling any command, including `version`.

Go identifies frozen module v1.0.0 with CMVP certificate 5247. The exact binary, operating environment, algorithms used, entropy path and surrounding application must still be assessed against the module security policy. This image does not assert whole-product certification. [Go FIPS documentation](https://go.dev/doc/security/fips140).

Go 1.27.2 is selected under the current two-major-release support policy; the previous Go 1.25 builder is outside that window. Base digests are immutable inputs, not an automatic update mechanism. Review and rebuild supported inputs through the signed appliance release process. [Go release history and support policy](https://go.dev/doc/devel/release).

## Remaining release evidence

Record the final source revision, immutable image manifest, verified OCI archive, dependency/license inventory and vulnerability assessment with each release. The image verifier is an isolated build check. Guest boot, encrypted mounts, split-process status, TLS/syslog, database migrations, SSO, update recovery and scale qualification remain separate acceptance gates in `docs/RELEASE_ACCEPTANCE.md`.
