# Private schema 4 appliance builds

Schema 4 can be built as a **private, unsealed qualification guest**. It is not
an accepted OVA or a release. This path permits testing the current factory
initialization implementation before distribution is authorized.

Pass `--private-qualification` to `appliance/packer/prepare_provenance.py`,
along with `--schema-revision 4` and `--restore-auth-evidence` pointing to the
exact application's build and HTTP authentication receipts. The normal source,
four-image bundle, publisher-input and authentication checks still run.
The captured descriptor records `private_qualification: true`.

Stage that captured source with `appliance/packer/stage_sources.py`. Run Packer
with `seal_image=false`, unique output and recovery paths, and a unique build
SSH key. Keep all output on the approved development volume. Preserve the
frozen source manifest and any dirty source patch with the candidate.

This does not change the public release policy:

- Default schema 4 provenance capture still refuses.
- The private marker must be the JSON boolean `true`, with schema 4 and the
  authentication evidence inventory. Changed evidence is rejected.
- The installer and fixed boot verifier accept these measured private inputs.
- The sealer's `require_factory=True` check still refuses schema 4.
- Release assembly still refuses schema 4.
- Firstboot still requires its existing host, kernel crypto, encrypted storage
  and runtime checks. The private marker does not bypass them.

The schema 4 initialization coordinator must still prove completion before
installed-release enrollment. Creating a private disk does not establish that
initialization, restore, updates, or either hypervisor has passed acceptance.

## Local launcher

Packer's plugin uses a Unix-domain socket beneath `TMPDIR`. The full socket path
must fit Linux's 108-byte `sun_path`, including the terminating byte. Use a short,
unique T9 scratch directory; deeply nested build-output paths can make plugin
startup fail with `listen unix ...: bind: invalid argument` before a VM starts.
Clean up only the completed run's owned temporary containers and scratch.
Retain its disks, recovery links, logs, source, and access material.
