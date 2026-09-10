# DISA STIG alignment

The selected policy intent uses current RHEL 9 DISA STIG requirements as a security reference, with explicit Rocky applicability review. RHEL's OpenSCAP profile ID is `xccdf_org.ssgproject.content_profile_stig`. A profile aimed at RHEL can produce not-applicable results on Rocky; that result is not compliance. [Red Hat STIG guidance](https://access.redhat.com/compliance/disa-stig)

Pin the datastream/package version, profile ID, SHA-256, STIG revision and any tailoring. Re-evaluate upstream changes before applying new content. Do not assume an older datastream implements the currently published STIG revision.

Unified policy should apply overlapping requirements once, choose the stricter compatible setting, favor documented STIG precedence for direct conflicts, and record application exceptions explicitly. Container namespaces, mount options, FIPS cryptography, identity integrations, service accounts and network forwarding require careful control-level review. No control can be silently marked passed because it was skipped for compatibility.

The repository currently implements assessment plumbing and baseline selection validation, not a reviewed full STIG remediation or certified Unified profile. CIS and STIG reports stay separate. Manual and site-specific controls remain visible and cannot be converted to automated passes.
