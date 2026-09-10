# CIS Rocky Linux 9 alignment

The CIS site lists Rocky Linux 9 Benchmark v3.0.0 as of the 2026-09-07 research date. Its separately listed Build Kit version differs. Always record the exact benchmark revision and assessment content; do not identify a v2 build kit as the v3 benchmark. [CIS Rocky Linux benchmarks](https://www.cisecurity.org/benchmark/rocky_linux)

CIS Level 2 is an intended selectable baseline. This repository does not redistribute CIS benchmark PDFs or restricted Build Kit content. Obtain content through CIS according to the applicable licensing terms. A source-code license for Captain’s Log does not grant rights to third-party benchmark content.

The host scanner requires an exact root-owned datastream, SHA-256, explicit profile ID and an applicability review for Rocky 9. It does not guess the RHEL product ID or skip failing controls. The current minimal hardening recipe is not sufficient evidence of CIS Level 2 alignment. Every release needs a full control assessment, manual-control review, justified exceptions and regression testing of ingestion/authentication/storage.

Use “CIS Level 2 aligned” only when release evidence supports it. Do not use “CIS certified” without formal authorization. See [compliance](COMPLIANCE.md) for policy selection and report semantics.
