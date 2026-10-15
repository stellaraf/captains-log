# Reviewed compliance-content transactions

The development implementation adds signed, content-only baseline transactions to the existing host/application update workflow. It is source-tested; neither a production content release nor a native appliance content upgrade is accepted by this document. Scanner RPMs and executable check engines still require their separate qualified OS recipe. This is not all-software update acceptance.

## Install the capability before enrolling content

An appliance running the published `11d4d84` coordinator cannot execute this new contract. Use three explicit releases in order:

1. Install a normal compatible **host + application capability release**, with no `content_enrollment` field and no `baseline` component. Complete health, authorized AIDE acceptance and finalization so the new coordinator is active.
2. Publish a later signed host + application release with top-level `"content_enrollment":"selected-baseline-v1"` and no `baseline` component. Its active coordinator measures the already selected, assessed and reviewed installation policy. It retains `content-enrollment.json`, checks the same identity again during health, and adds the measured `baseline` inventory only at commit.
3. Only then install signed host + application + `baseline` releases. `from_versions` must match the actual enrolled content version. Initial source identity is `sha256:<source-set-digest>`; subsequent content versions are the signed semantic version, measured from the retained immutable transition.

Do not put the enrollment flag on the capability release and assume the old coordinator implements it. Old coordinators can ignore an unfamiliar top-level field; an ignored flag is not enrollment. Verify that the later release's accepted `current.json` contains the measured `baseline` identity before publishing a content update. A coordinator which returns no exact content health receipt cannot commit enrollment under this implementation.

First boot remains in its original order. Bootstrap enrolls host and OCI identities before the console selects/hardens the baseline. It does not fabricate a baseline component or rewrite the original enrollment after selection. The later explicit bridge is the only introduction of measured content identity.

## Signed content archive

The assembler accepts `--content-archive` only for a paired host/application/baseline release. The signed baseline component names `baseline-content.tar`, a semantic version, supported `from_versions`, `content_schema:1`, `descriptor_sha256`, and `rollback_safe:true`. The USTAR archive has only bounded root-owned regular mode-0644 files; no symlinks, extensions, executables, hooks, directories or trailing nonzero archive data.

`content.json` identifies schema 1, kind `captains-log-compliance-content-v1`, platform `rocky9-x86_64`, source URL/revision, the exact scanner NEVRA and hash of `oscap --version`, and every file's size/SHA-256. It supplies reviewed CIS, STIG and Unified policy templates. All source references must resolve inside the signed inventory. The data stream contract permits OVAL/OCIL assessment data and refuses SCE, embedded scripts/check content, remote references and XCCDF `fix` remediation bodies. It never strips vendor content automatically or runs remediation during an update.

A raw vendor SSG data stream containing these executable/remediation constructs therefore does not qualify merely because it is vendor-signed. An assessment-only derivative needs an explicit source, coverage and licensing review, including any control that becomes manual-only or loses automated coverage. The source-generation procedure and real scanner qualification are release acceptance gates. The scanner/plugin identity must remain unchanged; `openscap*` and `scap-security-guide` cannot bypass this contract through the generic inert RPM path.

## Site authority and preflight review

The installed baseline, installation/selection IDs, site rule/group/value choices, exceptions, Unified decisions, original reviewer/rationale and original expiry remain retained. Removed or renamed references fail validation; the implementation does not silently drop them. A content signature establishes publisher provenance, not a customer's approval of changed controls.

Byte-identical source and unchanged effective selection can continue without new semantic approval. Otherwise preflight writes `content-review-request.json` and stops before service maintenance. Inspect the signed source, exact candidate policy and semantic diff, then obtain the template:

```sh
nebulalog-baseline content-review-template --stage /var/lib/nebulalog/manager/updates/releases/RETAINED_STAGE
nebulalog-baseline content-review --stage /var/lib/nebulalog/manager/updates/releases/RETAINED_STAGE \
  --review-file /root/reviewed-content.json --confirm-candidate-policy-sha256 EXACT_SHA256
```

The review must identify the exact installation, previous policy, candidate policy and archive; include reviewer, rationale and explicit control-semantics approval; and expire no later than the original authority or 90 days. Approval does not approve scan findings. Retry installation of the same signed release after review; the failed stage and review remain immutable.

Preflight also assesses **both the candidate policy and the old policy required for rollback**, before activation. Findings require explicit review of the printed retained assessment directory using the existing baseline review commands with that directory as `--configuration` and the installed setup file as `--setup`. Use `review-template`, review every exception/manual evidence item, then `review --review-file ... --confirm-assessment-sha256 ...`; do not rescan over the retained review target. The original active policy and its approvals are unchanged. A later retry scans afresh in its own stage and may continue only the exact reviewed evidence. All-pass results still require content applicability/selection authority; they do not override a changed-semantics review requirement.

## Exact evidence continuation

Content assessments retain standalone XCCDF XML, HTML, full ARF, exact source/tailoring/mapping, policy, scanner identity and host provenance. Before and after activation the boot, machine, kernel, complete RPM inventory and host security controls must agree. The ARF comparison includes the complete source, assets, relationships, per-rule result and instance data, collected objects/items, OVAL definition/test/variable results and manual evidence scope. A changed object or value with the same `fail` status invalidates an exception.

Only generated XCCDF TestResult ID and explicit TestResult/rule evaluation times, plus OVAL **results/system-characteristics** generator timestamps, are excluded from evidence equality. Embedded source timestamps, generic IDs, object identities, messages, target facts and all other data remain substantive. OpenSCAP's standalone-to-ARF href rewrites are checked against exact internal benchmark, result and asset graph identities before correlating the reports; unresolved or duplicate identities refuse. Unsupported format variation conservatively refuses continuation.

A continuation receipt names both assessments and the original review digest. It does not rewrite the assessment an operator reviewed, renew expiry, change rationale or convert a manual attestation into an automated pass. Manual evidence files and each exception's expiry are checked again. Material change during activation causes health failure and rollback; if rollback's old-policy evidence also changed, maintenance remains held for explicit current review.

## Integrity, activation and recovery

Signed inactive generation files are deterministic and root-owned under `/usr/share/nebulalog/compliance-content/<generation>`. A protected owner/plan is published before additions. A preexisting foreign generation is never adopted, even if its bytes match. Partial owned publication can only continue with identical bytes and metadata. The active selected policy is unchanged during staging.

The existing host runtime plan becomes schema 2 only for this typed recipe. It binds the exact inactive additions and the single mode-0600 selected-policy before/after transition. AIDE preparation permits those exact additions, while ordinary unrelated changes still fail. Activation atomically selects the candidate policy; health runs a fresh assessment and accepts the exact authorized AIDE change using the existing authenticated database/CAS history. No baseline recapture or broad exclusion is introduced.

Commit records the actually measured content version/generation/policy/engine. Finalization remeasures it before clearing maintenance. Rollback restores the exact retained previous policy and inventory, accepts the typed AIDE rollback, verifies fresh old-policy health and leaves immutable candidate/source/review history intact. Historical plan verification does not renew an expired approval; expiry cannot by itself authorize new selection, but it also does not erase the historical authority to restore old bytes. Unknown hook/native command outcomes remain held under the existing component lifetime protocol and are never replayed based only on PID or lock absence.

Source fixtures cover signed orchestration, protected filesystem publication/restoration, real AIDE Python history/CAS with injected scanner responses, and full ARF parsing/review semantics with injected host/scanner observations. The separately retained actual OpenSCAP synthetic ARF fixture qualifies format/completion only. Native appliance content activation, approved vendor-derived CIS/STIG/Unified coverage, a real change/rollback and scanner RPM upgrades remain distinct release acceptance gates.
