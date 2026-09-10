# LUKS2 and recovery

Each deployed data disk must receive its own LUKS2 volume key after FIPS is active. No encryption key is shipped in the image. The additional-disk implementation uses LUKS2, AES-XTS with a 512-bit key setting (two AES-256 keys), SHA-256 and PBKDF2 for the FIPS-compatible keyslot path, subject to verification against the actual module security policy.

Console passphrase unlock is the safe baseline. The unlock credential is provided through a root-only private runtime file, tested before changes, and never included in logs or command-line text. Each additional disk gets a distinct generated recovery credential, tested before pool extension. Export it to a protected external escrow and test restoration. Do not store the only key inside the filesystem it unlocks.

TPM2/vTPM unlock is a future **qualified option**, not currently a working default. Its policy must account for PCR changes during kernel/boot updates, hypervisor vTPM backups and recovery after migration. Automatic first boot must not silently create a plaintext persistent key on the system disk to avoid a console prompt.

Back up LUKS headers to encrypted off-appliance storage using the recovery runbook for the exact disk identity. A header backup is sensitive: old keyslot data can revive a revoked passphrase when used with an older header. Header backup is not a copy of log data. Losing all enrolled credentials and recovery/header material can make logs unrecoverable.

`cryptsetup resize` expands the active mapping; it does not expand GPT, LVM or XFS. LUKS2 can require re-authentication for resize. [Upstream resize behavior](https://gitlab.com/cryptsetup/cryptsetup/-/raw/main/man/cryptsetup-resize.8.adoc)

See [storage expansion](STORAGE_EXPANSION.md) for guardrails and current unexecuted VM tests. Initial disk enrollment and full reboot/unlock recovery are acceptance blockers.
