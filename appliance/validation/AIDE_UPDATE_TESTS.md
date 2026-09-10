# Native AIDE update tests

`aide_update_native.py` is the exact scanner harness used for the six native
Rocky AIDE tests recorded in `docs/validation/UPDATE_EXECUTION.md`. It uses the
actual installed AIDE scanner and SELinux `restorecon` command on isolated test
files. The storage identity, source facts, and runtime plan are fixtures.

Run this separately from the read-only installed-guest collector, on a disposable
Rocky Linux 9 x86_64 test guest with AIDE 0.19.2, FIPS enabled and SELinux Enforcing.
The source checkout must include `appliance/tests`. As root, from the checkout:

```sh
CAPTAINS_LOG_TEST_RECEIPTS=/root/captains-log-aide-results-01 \
PYTHONPATH=appliance:appliance/tests \
python3 -B appliance/validation/aide_update_native.py
```

The output directory must not already exist. The harness writes scanner reports
and a structured result there, and creates and cleans its own temporary fixture
files. It does not enroll the appliance or adopt the appliance's integrity
database. Preserve the recorded installed AIDE/RPM version separately; the
runner's `aide_version` field identifies its qualified test version.

The cases cover a forward and rollback transition, unrelated drift during the
scan, unrelated changes in the report, interrupted database replacement,
interrupted scanning, and actual extended-attribute drift. Passing them is
evidence for the scanner integration only. Full appliance update, authentication,
log continuity, boot and hypervisor acceptance require their own native results.
