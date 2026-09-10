# Contributing

Use a branch and include the problem, behavior change, tests and compatibility
impact in the pull request. Run the Go race tests and frontend build/tests before
submission. Preserve unrelated workspace changes.

Parser changes require a canonical vendor source and a sanitized fixture.
Never contribute customer payloads, API keys, private IP inventories, encryption
keys or passwords. Mark fixtures as synthetic. Keep wire family, derived view,
schema registry revision and actual PAN-OS version distinct.

Security-sensitive changes require tests for failure paths. Never disable
authentication, SELinux, FIPS or signature validation to pass tests. Do not mark a
release acceptance gate complete without reproducible evidence. Document
architecture changes in an ADR. Original contributions to Captain’s Log are
licensed under AGPL-3.0-only. Preserve third-party copyright notices and licenses;
identify any contributed third-party material and its license. See
[LICENSING.md](LICENSING.md).
