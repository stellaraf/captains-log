# Compliance assessment and first-boot review

Captain’s Log separates **selected policy**, **completed assessment**, **automated results**, and **explicit review**. Selecting Unified, producing an HTML report, or approving an exception does not make failed rules pass and does not certify the appliance. FIPS, encryption, SELinux, auditing and firewall requirements remain mandatory independently of baseline selection.

The first-boot workflow is implemented by `nebulalog-baseline`. Its assessment command invokes the `security.scan` OpenSCAP adapter without `--remediate`, preserves evidence on encrypted appliance storage, and binds a separate review receipt to the installation and exact assessment. These are host workflow commands; the final administrator-facing UI integration and actual guest qualification remain release requirements.

## Installed content and applicability

Run `nebulalog-baseline inventory` on the Rocky guest. It inventories the actual installed `openscap-scanner` and `scap-security-guide` RPM versions, calls `oscap info`, and parses exact profile IDs, titles, references, benchmark versions and platform declarations. Missing scanner/content is reported as unavailable. No profile is automatically approved. The default directory is `/usr/share/xml/scap/ssg/content`; use absolute paths when supplying another reviewed source.

The official Rocky 9 package inspected on 2026-09-07 was `scap-security-guide-0.1.81-1.el9_8.rocky.1.1.noarch`. It contains `ssg-rl9-ds.xml`, SHA-256 `716e6b620d990079b1159d3cf4fcb9fe61d42a0cdd3820645f4528aafee4ff3b`, and Rocky 9 platform checks. Its candidate profile IDs are:

| Intent | Actual profile ID | Content described by the inspected package |
| --- | --- | --- |
| CIS Level 2 Server | `xccdf_org.ssgproject.content_profile_cis` | CIS **RHEL 9 v2.0.0** |
| STIG | `xccdf_org.ssgproject.content_profile_stig` | **RHEL 9 STIG V2R8** |

The current CIS Rocky Linux 9 benchmark is v3.0.0. The packaged RHEL-based profile must not be relabeled Rocky CIS v3 or assumed to cover it. Native Rocky platform recognition establishes intended scanner applicability; coverage of the requested benchmark needs a documented review and any missing controls. Retain the installed package's actual version/hash instead of blindly copying this dated inventory. [Official Rocky package](https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/s/scap-security-guide-0.1.81-1.el9_8.rocky.1.1.noarch.rpm), [CIS Rocky benchmark](https://www.cisecurity.org/benchmark/rocky_linux), [ComplianceAsCode usage](https://github.com/ComplianceAsCode/content).

## Licensing

SCAP Security Guide / ComplianceAsCode content uses BSD-3-Clause. It can be redistributed under those terms, including required notices and non-endorsement conditions; availability of this open-source content must not be confused with permission to redistribute separately supplied CIS material. [Upstream license](https://raw.githubusercontent.com/ComplianceAsCode/content/master/LICENSE).

CIS's free benchmark PDF license is CC BY-NC-SA 4.0. CIS End User membership also restricts distributing SecureSuite products or customized benchmarks as part of an offering. A download or end-user membership alone does not authorize commercial appliance redistribution of CIS-supplied benchmark/build-kit material. Review rights for the exact inputs used; retain the decision in the content review. [CIS terms](https://www.cisecurity.org/terms-and-conditions-table-of-contents), [free PDF license](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode), [End User terms](https://www.cisecurity.org/terms-and-conditions-table-of-contents/end-user-organization-membership-agreement).

## Select a reviewed policy

The command reads the installation ID and chosen baseline from `/var/lib/nebulalog/configuration/bootstrap/setup.json`. Policy selection must match that choice: `cis-level2`, `stig`, or `unified`. The selected policy is written to `/var/lib/nebulalog/configuration/security-policy.json`; lifecycle adapters must use that same canonical path.

An input policy uses this shape. The placeholders and `approved: false` intentionally make this example **unapproved**; the qualified content reviewer supplies actual evidence and dates.

```json
{
  "schema": 1,
  "baseline": "cis-level2",
  "assessments": [{
    "kind": "cis",
    "platform": "rocky9",
    "reviewed": true,
    "datastream": "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml",
    "sha256": "REPLACE_WITH_INSTALLED_CONTENT_SHA256",
    "profile_id": "xccdf_org.ssgproject.content_profile_cis",
    "source_url": "REPLACE_WITH_EXACT_PUBLISHER_SOURCE",
    "content_revision": "REPLACE_WITH_ACTUAL_BENCHMARK_REVISION",
    "content_review": {
      "approved": false,
      "reviewer": "REPLACE_WITH_RESPONSIBLE_REVIEWER",
      "reviewed_at": "REPLACE_WITH_ISO8601_TIMESTAMP_WITH_TIMEZONE",
      "expires_at": "REPLACE_WITH_ISO8601_TIMESTAMP_WITH_TIMEZONE",
      "platform_basis": "Document why the exact checks apply to this Rocky 9 build",
      "benchmark_basis": "Document requested benchmark coverage, revision differences and missing controls",
      "license_basis": "Document the exact content license and redistribution decision"
    }
  }]
}
```

Content review expires within one year. The datastream must contain the exact chosen profile, its appropriate CIS L2 Server/STIG title, and native Rocky 9 CPE declaration. The scanner's real results remain the runtime applicability evidence. Changed content hashes or expired reviews stop assessment and invalidate current acceptance.

For Unified, include exactly one CIS and one STIG assessment plus `unified_mapping: {"path": "/absolute/path/to/reviewed-mapping.json", "sha256": "ACTUAL_SHA256"}`. The mapping document requires:

- `schema: 1`, `baseline: "unified"`, `coverage_reviewed: true`, and a `review` object with the same explicit review fields as above.
- `assessments` keyed by `cis` and `stig`, each binding `sha256`, `base_profile_id`, effective `profile_id`, `tailoring_sha256` (null for an untailored profile), and `selection_sha256`. The selection hash covers canonical rule, value and group decisions, including their review rationale. `assessment_binding` and the factory review-input builder produce this exact identity. Paths and initial-console reviewer/timestamps are excluded; they cannot authorize a change in the assessment's meaning.
- A nonempty `controls` array. Each entry records unique `control`, `cis_rule`, `stig_rule`, `decision`, `rationale`, and `effective_setting`.

Decisions are `same-once`, `stricter-compatible`, `direct-conflict`, `application-exception`, `cis-only`, or `stig-only`. Rule IDs must exist in the corresponding pinned benchmark; an absent side uses JSON null for a one-sided control. Duplicate control IDs/pairs and omitted original benchmark rules are rejected. Document STIG precedence for direct conflicts, or the explicit reason for a different decision. Machine validation checks complete rule coverage and binding; semantic compatibility and the correctness of effective settings still require review. The assessment operation does not remediate the host. The separate initial-hardening operation can apply one explicitly reviewed merged profile as described below.

After reviewing the concrete policy and its hash:

```sh
nebulalog-baseline select --policy /absolute/path/to/reviewed-policy.json --confirm-policy-sha256 ACTUAL_POLICY_SHA256
nebulalog-baseline scan
nebulalog-baseline status
```

## Assessment evidence

### Initial application of a selected policy

The initial setup console now exposes **HARDENING** before file-integrity
enrollment. For a selected, reviewed CIS Level 2 or STIG policy, it confirms the
operation locally and invokes `nebulalog-baseline remediate` with the selected
policy's exact hash. The equivalent CLI is:

```sh
nebulalog-baseline remediate --confirm-policy-sha256 ACTUAL_SELECTED_POLICY_SHA256
```

This operation requires the actual installation's encrypted configuration and
host-ready gate. It serializes with firstboot, runtime preparation, and AIDE;
completed setup or any existing AIDE enrollment state refuses initial
remediation. It snapshots the reviewed SCAP content, applies that profile's
OpenSCAP fixes, and retains the policy, inputs, reports, scanner exit code, and
host security postconditions in `configuration/baseline-remediations/`.
Existing assessment acceptance is invalidated before changes begin. A failed
run preserves its evidence and requires review; it does not claim rollback of
arbitrary operating-system fixes.

A completed remediation command is not compliance acceptance. Findings can
remain even with successful command execution. Enroll file integrity after
applying hardening, then perform a fresh assessment and findings review.
Unified remediation requires a `unified_remediation` profile derived from the
pinned STIG base and bound by the mapping to its exact source, effective profile
and tailoring hash. Every control decision must name its `applied_rule`, or an
explicit `application-exception` with no applied rule. The effective merged rule
set must equal that register. One merged profile is applied once; CIS and STIG
are then assessed independently. Applying the two original profiles sequentially
would not implement the reviewed conflict mapping.

This implementation still needs native guest qualification and a complete,
reviewed Unified factory policy for out-of-box setup. Source changes do not
establish that an existing frozen candidate contains them.

Assessment runs only as root on the actual supported Rocky 9 x86_64 guest. Each scan records installation ID, selected policy/hash, machine identity hash, OS/kernel and scanner/package versions, host security status, raw per-rule results, counts and original automated result. It retains policy, datastream, XML and HTML snapshots under `configuration/baseline-assessments/<scan-id>/` with SHA-256 hashes. Unified also retains its reviewed mapping. The current receipt is `configuration/baseline-assessment.json`.

A durable `baseline-attempt.json` marks the newest scan running, failed, or complete. A failed or interrupted rescan invalidates previous approval while preserving previous evidence. A fresh selection or successful scan always needs fresh review. Source/package/kernel/machine changes, missing/tampered artifacts, and altered summaries invalidate current acceptance.

A successful process exit is not sufficient. Empty/all-notapplicable/all-notselected reports, unknown results, scanner execution errors, and unexpectedly unchecked automated rules cannot complete the first-boot gate. Exit 2 with valid reports preserves failing rules as findings. No numeric score is converted into an appliance compliance claim.

### Manual controls

Some actual STIG rules have no automated check or use OCIL manual checks. The adapter identifies these from the **pinned source Rule**, not from a reviewer-supplied flag. Only a rule with no check or exclusively `http://scap.nist.gov/schema/ocil/2` checks may receive a `manual-pass` disposition for a `notchecked` result. Missing OVAL results, unknown engines, mixed automated/manual checks, errors and unknown results remain blocked. [OpenSCAP check engines](https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html#_check_engines).

A manual pass requires an actual root-owned evidence file and its SHA-256 in `manual_evidence: {"path": "/absolute/path/to/evidence", "sha256": "ACTUAL_SHA256"}`, alongside the reviewer, method/observations, reason and approval reference. Changes to that evidence invalidate review. The original automated `notchecked` result remains visible and never becomes an automated pass. An all-unchecked report remains unusable even if the controls are manual.

## Explicit findings review

`nebulalog-baseline review-template` produces an unapproved JSON draft bound to the current assessment hash. Save it privately, inspect every report and profile exclusion, and complete the fields. Even an all-pass automated report requires explicit human approval.

The top-level receipt requires `approved: true`, `selection_reviewed: true`, reviewer, rationale, timezone-bearing `reviewed_at` after the scan, and an `expires_at` within 90 days. Every finding must appear exactly once with matching kind/rule/result. Each finding needs disposition, reason, compensating control, owner, approval reference, evidence, and expiration no later than the overall review:

| Original result | Permitted review |
| --- | --- |
| `fail` | `exception`, with documented accepted risk and compensating control |
| `notapplicable` | `not-applicable`, with applicability evidence |
| Source-declared manual `notchecked` | `manual-pass`, with hashed manual evidence |
| `informational` | `manual-review` |
| Unexpected `notchecked`, `error`, `unknown`, `fixed` | Resolve the condition and rescan; no approval override |

`notselected` results remain counted and visible; they are not findings. The explicit profile/selection review covers which controls the chosen profile excludes. Application-specific exceptions never erase machine failures or weaken the separately required host controls.

```sh
nebulalog-baseline review --review-file /absolute/path/to/completed-review.json --confirm-assessment-sha256 ACTUAL_ASSESSMENT_SHA256
nebulalog-baseline status
```

The command writes `configuration/baseline-review.json` and an audit event. `baseline_assessed` means the latest scan has usable, current evidence; `baseline_review_complete` means that exact evidence has a valid explicit review and all required manual/exception records. Automated pass/fail remains independent. The bootstrap integration calls `firstboot_checks(configuration, installation_id, baseline)`; it receives only those two booleans and fails closed on missing/stale evidence.

## Current boundaries and verification

The legacy `nebulalog compliance status` measures host controls, and `nebulalog compliance scan --policy ... --output ...` remains the low-level scanner. Running it alone does not create the installation-bound first-boot review receipt. The final CLI/UI dispatcher must use the baseline workflow for that purpose.

Tailored rule selections are supported with explicit base/effective-profile binding as described below. Native qualification of initial remediation, signed content updates, comprehensive unified coverage mapping, and the final UI workflow remain required. [OpenSCAP tailoring documentation](https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html).

Targeted fixture tests exercise actual scanner command construction, retained artifacts, strict selection, explicit approval, manual evidence, failure/expiry/tamper gates, failed-rescan invalidation and unavailable content. They do not prove guest results or benchmark alignment. Release evidence still requires scans on each selected baseline, a qualified coverage/license review, deliberate failure/manual/exception cases, and actual first-boot integration on the built Rocky appliance.


### Appliance profile tailoring

The baseline manager supports a restricted XCCDF 1.2 tailoring format for
appliance-specific rule selections. A reviewed policy must name both the actual
installed `base_profile_id` and distinct effective `profile_id`, pin
`tailoring_sha256`, and include `tailoring_decisions` with a rule ID, boolean
selection, rationale, and effective control for every override. The tailoring
must contain exactly one profile extending that base, with a local datastream
filename in its benchmark reference. Extra profiles, free-form values, group
disabling, embedded fixes, unknown rules, and unrecorded selections are refused.
Enabling a group requires the complete source-derived descendant inventory and
explicit rationale, as well as exact effective-rule coverage for Unified.

Assessment and remediation explicitly pass the effective profile and tailoring
file to OpenSCAP. Remediation captures both inputs together before applying
fixes; assessment retains the exact tailoring alongside its policy and reports.
Tailoring does not grant compliance approval: excluded controls still require
explicit findings/profile review. The packaged CIS source identifies a RHEL
benchmark; tailoring must not be advertised as proof of full coverage of the
current Rocky-specific CIS benchmark.

Factory tailoring choices and their native-guest validation remain release
requirements. In particular, blindly applying the raw CIS profile can remove
httpd, and crypto-policy remediations can conflict with the appliance FIPS
configuration. Those conflicts must be resolved and documented before offering
an out-of-box profile as release-ready.


### Bundled first-boot content

The factory image installs `baseline-catalog.json`, `baseline-cis.xml`, and
`baseline-stig.xml` as measured host-generation defaults. The catalog pins the
Rocky RPM datastream SHA-256 and exact benchmark versions; a changed installed
datastream is refused until its adaptation is reviewed and repackaged.

When no policy has been selected, the local HARDENING action presents the
benchmark limitations and every appliance exception. The operator explicitly
accepts that content and enters a name for a 90-day content-review record.
A separate APPLY confirmation runs remediation. Neither action creates a
compliance findings approval or completes setup. Cancellation before content
acceptance writes no policy. An already selected policy retains its identity.

The shipped candidates preserve the HTTPS endpoint, pinned FIPS policy, disabled
SSH access, and the appliance's installation-bound AIDE lifecycle. These are
explicit exceptions, not claims that the corresponding benchmark controls have
passed. Unified remains unavailable until its executable conflict mapping is
complete. The candidates require native OpenSCAP and appliance service testing
before release; unit tests alone do not qualify their effective hardening.


The October 12 build candidates use Rocky `scap-security-guide-0.1.82-2.el9_8.rocky.1.1`
with datastream SHA-256
`769e4de0ee8ee67334745f97088043591d97694f3f494d07d9d0fa44fed02a51`.
Its CIS profile still identifies RHEL 9 v2.0.0; its STIG profile identifies V2R9.
OpenSCAP 1.3.14 parsed both effective profiles, validated their XSD schemas, and
generated syntactically valid shell remediation plans with the declared fixes
excluded and no crypto-policy reset remaining. The Rocky tool lacks Tailoring
Schematron rules, so XSD validation explicitly used `--skip-schematron`; this is
not a claim of full Schematron validation or guest compliance. The generated
plans contain 396 CIS and 469 STIG rule entries, including rules without fixes.
No generated plan was executed as part of this tooling validation.


To resolve differing benchmark values, a tailoring may use `refine-value` with
an exact named selector already defined by the pinned datastream. Every override
must also appear in `tailoring_values` as `value_id`, `selector`, and `rationale`.
Unknown selectors, duplicate decisions, free-form `set-value`, and XML overrides
without matching policy decisions are refused. First boot displays value choices
alongside rule exceptions. This mechanism supports explicit stronger-setting and
conflict decisions; it does not itself establish a complete Unified mapping.

### Unified factory preparation and value conflicts

The factory loader supports a reviewed Unified catalog entry with fixed files
`baseline-unified.xml` and `baseline-unified-mapping.json`. The catalog binds
both hashes. Its two independent assessment candidates must remain the exact
bundled CIS/STIG candidates recorded in the coverage review. Reusing profile IDs
after changing assessment rules, values, tailoring bytes or decision rationale
does not preserve that approval. An older mapping with only source hash and
profile ID must undergo a fresh exact selection review. Initial-console content acceptance does not create
or renew the mapping's coverage review, approve a site exception, or accept scan
findings. Missing, expired, unreviewed or changed mappings are refused. The
currently shipped catalog still contains only CIS and STIG: this loader does
not make the outstanding Unified content review complete.

For an executable Unified policy, the register also requires a
`value_decisions` entry for every differing original CIS/STIG source value.
Each entry binds `value_id`, both original `choices` (selector and value), a
decision, rationale and the exact merged `effective` selector/value. Decisions
are `stricter-compatible`, `direct-conflict`, or `application-exception`.
Conflicts are measured before appliance tailoring, so changing both assessment
profiles cannot hide a difference. Duplicate, missing or invented choices, and
a merged value that differs from the register, are refused. The validator does
not infer that a larger number, smaller number, or a STIG value is always more
secure; those semantics require explicit review.

Release-content maintainers can generate deterministic, unapproved review input
using the pinned datastream and OpenSCAP build tooling:

```sh
PYTHONPATH=appliance python3 appliance/packer/build_unified_baseline.py \
  --catalog-directory /absolute/path/to/factory-content review-inputs \
  --datastream /absolute/path/to/ssg-rl9-ds.xml > unified-review-draft.json
```

The output keeps `coverage_reviewed: false`, `review.approved: false` and every
decision pending. It lists all original selected rules, source value conflicts,
and existing appliance adaptations. Matching rule identifiers alone do not
prove that different rules can safely modify the same resource.

After a complete merged policy and its coverage/conflict review exist, the
`package` action validates them and captures fixed-name files into a new output
directory. It refuses to overwrite an existing directory or package incomplete
review. It preserves the existing mapping review unchanged:

```sh
PYTHONPATH=appliance python3 appliance/packer/build_unified_baseline.py \
  --catalog-directory /absolute/path/to/factory-content package \
  --policy /absolute/path/to/reviewed-unified-policy.json \
  --output /absolute/path/to/new-unified-package
```

The package is build input. It still needs inclusion in the measured host
payload, native OpenSCAP validation, guest remediation and fresh independent
assessments. Neither the package receipt nor the fixture tests claim release
qualification.
