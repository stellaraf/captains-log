# HKDF diagnostic (not a kernel repair)

`hkdf_probe.py` prepares two private diagnostic modules from the exact reviewed
Rocky 5.14.0-687.56.1.el9_8 `crypto/hkdf.c` SHA-256. The control retains the
original implementation. The candidate zero-pads short public salts to 14 bytes
when the HMAC block size permits it. All 15 vendor known-answer vectors remain
unchanged. Generic HMAC short-key rejection remains in force.

The modules export no symbols, replace no kernel functions, and register no
crypto provider. They require FIPS mode and enabled crypto tests. A passing
candidate does not repair the installed kernel or establish FIPS qualification.

Prepare into a new directory on T9:

```sh
python3 appliance/experiments/hkdf_probe.py --vendor-source /path/to/hkdf.c --output /path/to/new-probe
```

Build against the exact signed vendor kernel-devel package and matching config.
Use a case-sensitive Linux filesystem: extraction onto the case-insensitive T9
filesystem causes header-name collisions. A Docker named volume is suitable only
when Docker's data directory is verified to reside on T9. Sign diagnostic modules
with the disposable qualification signer; never include private signing keys in
source, guest disks or release artifacts.

## Recorded native result, October 12, 2026

Evidence is retained under `/Volumes/T9/StellarBuilds/CaptainsLog/build-20261012`:

- `logs/hkdf-native-probe-002.log`: original control refused with the HKDF failure;
  candidate loaded and passed 15 vectors, with the HMAC guard retained.
- `outputs/hkdf-probe-signed-002/receipt.json`: exact signed and unsigned hashes,
  CMS verification and target kernel version.
- `logs/hkdf-probe-build-002.log`: case-sensitive kernel-devel build.
- `logs/firstboot-after-hkdf-diagnostic.log`: firstboot still refused because the
  original installed kernel reports its cryptographic self-test failure.

Both probes used boot `25e40032-f24b-419f-a868-3b4d0cf2ccab`, kernel FIPS flag 1
and signature enforcement Y. The candidate diagnostic remains distinct from a
complete kernel build, signing/update lifecycle, boot acceptance and independent
cryptographic qualification. None of those production repair gates passed here.
