> Product name update (September 9, 2026): the user renamed this appliance **Captain’s Log**, with the repository slug **captains-log**. The original request below is retained verbatim for traceability; its product-name references are superseded by this update. Internal compatibility identifiers remain as documented in [PRODUCT_NAME.md](PRODUCT_NAME.md).

> License update: the user selected **AGPL-3.0-only** for original Captain’s Log
> code. This supersedes the Apache-2.0 project-license requirement in the original
> request retained below. Third-party licenses remain unchanged; see
> [LICENSING.md](../LICENSING.md).

You are building a production-quality open-source security appliance called:

NEBULALOG

Tagline:

    Fast, local-first PAN-OS log collection and search.

GitHub organization:

    stellaraf

Repository:

    stellaraf/nebulalog

License:

    Apache-2.0


======================================================================
MISSION
======================================================================

Build NebulaLog, a hardened self-hosted log collection and exploration appliance
designed primarily for Palo Alto Networks PAN-OS firewalls.

The primary use case is providing centralized log storage for:

- PA-410 series firewalls with insufficient/on-device log storage limitations
- firewalls where local log searching is slow or tedious
- environments with multiple standalone Palo Alto firewalls
- organizations that want a fast centralized log viewer without deploying
  Panorama or a full SIEM

NebulaLog must receive standard PAN-OS Syslog, parse it, retain it locally, and
provide a browser experience immediately familiar to an administrator accustomed
to:

    PAN-OS
      -> Monitor
         -> Logs

The supplied PAN-OS screenshots are UX/workflow references.

Do NOT copy Palo Alto branding, logos, visual assets, or proprietary artwork.

Reproduce the workflow and information architecture, not the branding.


======================================================================
CORE PRODUCT PRINCIPLE
======================================================================

NebulaLog should feel like:

    "PAN-OS Monitor > Logs, except centralized, much faster, hardened,
     encrypted, and designed for long-term retention."

This is NOT intended to become a full SIEM in version 1.

Do not allow these to distract from the core product:

- SOAR
- ML detections
- endpoint telemetry
- giant dashboard systems
- Kubernetes
- Kafka
- cloud dependencies
- SaaS accounts
- unnecessary microservices

Priorities:

1. Never lose firewall logs unnecessarily.
2. Parse PAN-OS logs correctly.
3. Search them extremely quickly.
4. Support familiar PAN-OS filter syntax.
5. Make storage/retention easy to understand.
6. Make deployment extremely simple.
7. Make the appliance secure by default.
8. Make lifecycle/update management automatic.
9. Provide excellent documentation.


======================================================================
ARCHITECTURE
======================================================================

Production appliance:

    Rocky Linux 9

Security baseline:

    FIPS mode enabled
    LUKS2 encrypted data
    SELinux Enforcing
    firewalld
    auditd
    AIDE
    selectable CIS/STIG security baseline

Application runtime:

    Podman
    systemd Quadlets

Application stack:

    NebulaLog Web/API
    NebulaLog Syslog Ingest
    NebulaLog DNS Enrichment
    NebulaLog Appliance Manager / Updater
    Keycloak
    PostgreSQL
    ClickHouse


DATABASE RESPONSIBILITIES
-------------------------

CLICKHOUSE:

Use ClickHouse exclusively for high-volume firewall event/log data.

Store:

- Traffic
- Threat
- URL
- DNS
- WildFire
- GlobalProtect
- Authentication
- System
- Configuration
- User-ID
- supported PAN-OS log families
- original raw Syslog payload

ClickHouse is selected because NebulaLog must realistically support:

    tens of millions of events/day

and potentially:

    hundreds of millions or billions of retained records.


POSTGRESQL:

Use PostgreSQL for stateful application metadata.

Store:

- Keycloak database
- NebulaLog configuration
- firewall inventory
- saved queries
- favorites
- UI preferences
- column layouts
- RBAC mappings
- DNS configuration
- appliance configuration
- update history
- retention configuration
- audit/application metadata

Prefer separate PostgreSQL databases/users:

    keycloak
    nebulalog

with least-privilege access.

DO NOT use SQLite.


======================================================================
SYSLOG INGESTION
======================================================================

Provide native PAN-OS Syslog collection.

Support:

    UDP/514
    TCP/514
    TLS/6514

Ports must be configurable.

Support IPv4 and IPv6 where practical.

The collector must be optimized for bursts.

Implement:

- asynchronous ingestion
- buffering
- batching
- bounded queues
- backpressure
- disk-backed buffering/spooling where appropriate
- retry behavior
- graceful database outage handling

NEVER silently discard events.

Expose:

    Messages Received
    Messages Parsed
    Parse Failures
    Events Inserted
    Queue Depth
    Spool Usage
    Messages Dropped
    Events/sec
    Bytes/sec
    Last Event Received


======================================================================
PAN-OS LOG PARSING
======================================================================

Before implementing parsers, research CURRENT official Palo Alto documentation.

Use official PAN-OS Syslog Field Descriptions as the canonical reference.

PAN-OS schemas change between log type and PAN-OS release.

DO NOT create a parser that assumes:

    fixed field count
    fixed PAN-OS version
    one global CSV schema


Create a versioned schema registry.

Each record must retain:

    ingestion timestamp
    firewall-generated timestamp
    receive timestamp
    sender/source IP
    firewall serial
    firewall hostname/device name
    VSYS
    log type
    log subtype
    PAN-OS schema/version where determinable
    parser version
    parse status
    raw original event


Malformed/unrecognized events:

    MUST NOT BE DROPPED.

Store:

    raw event
    sender
    timestamp
    suspected log type
    parsing error

Expose them under:

    Administration
      -> Diagnostics
         -> Parsing


======================================================================
LOG CATEGORIES
======================================================================

Support PAN-OS Monitor-style organization.

Include where supported:

    Traffic
    Threat
    URL Filtering
    WildFire Submissions
    DNS Security
    Data Filtering
    HIP Match
    GlobalProtect
    IP-Tag
    User-ID
    Decryption
    Tunnel Inspection
    Configuration
    System
    Alarms
    Authentication
    Unified

Verify actual log types against current PAN-OS documentation.

Do not invent wire formats merely because a GUI category exists.

"Unified" should provide a cross-log-type search experience.


======================================================================
FIREWALL INVENTORY
======================================================================

Support multiple firewalls.

Identify devices using:

    firewall serial
    hostname
    sender IP

Automatically discover incoming devices.

Administration
  -> Firewalls

Display:

    Friendly Name
    Device Name
    Serial Number
    Sender/Management IP
    Site
    Tags
    PAN-OS Version where known
    First Seen
    Last Seen
    Average EPS
    Current EPS
    Peak EPS
    Events Today
    Status

Allow:

    Friendly Name
    Site
    Tags
    Notes


======================================================================
MAIN LOG UI
======================================================================

The primary UI must resemble the WORKFLOW of the supplied PAN-OS screenshots.

LEFT:

Logs
  Traffic
  Threat
  URL Filtering
  WildFire Submissions
  DNS Security
  Data Filtering
  HIP Match
  GlobalProtect
  IP-Tag
  User-ID
  Decryption
  Tunnel Inspection
  Configuration
  System
  Alarms
  Authentication
  Unified


TOP TOOLBAR:

    Filter Query
    Apply
    Clear
    Add Filter
    Save Filter
    Load Filter
    Refresh
    Pause/Resume
    Time Range
    Columns
    Export CSV
    Resolve Hostnames checkbox


LOG TABLE:

Must be dense and optimized for engineers.

Support:

    sortable columns
    show/hide columns
    reorder columns
    resize columns
    sticky headers
    horizontal scrolling
    virtualization
    persisted layouts
    per-log-type defaults
    row details
    pagination/cursor loading


TRAFFIC DEFAULT COLUMNS:

    Receive Time
    Type
    From Zone
    To Zone
    Source
    Source Hostname
    Source User
    Destination
    Destination Hostname
    Source Port
    Destination Port
    Application
    Previous Application
    Action
    Rule
    Session End Reason
    Bytes
    Bytes Sent
    Bytes Received
    Packets
    Session ID
    NAT Source
    NAT Destination
    Device
    VSYS


======================================================================
PAN-OS FILTER LANGUAGE
======================================================================

THIS IS A CRITICAL FEATURE.

Support filter syntax compatible with PAN-OS Monitor filters wherever practical.

Examples:

    ( addr.src in 10.150.1.161 )

    ( addr.dst in 1.1.1.1 )

    ( addr.src in 10.0.0.0/8 )

    ( app eq ssl )

    ( action eq allow )

    ( rule eq "Default Outbound" )

    ( port.dst eq 443 )

    ( zone.src eq trust )

    ( zone.dst eq untrust )

Combined:

    ( addr.src in 10.150.1.161 ) and ( port.dst eq 443 )

    ( app eq ssl ) or ( app eq web-browsing )

    ( addr.src in 10.0.0.0/8 ) and
    ( action eq allow ) and
    ( port.dst eq 443 )


Build a REAL compiler:

    Query String
        ↓
    Lexer
        ↓
    Parser
        ↓
    AST
        ↓
    Validation
        ↓
    Parameterized ClickHouse query


DO NOT use regex substitution as the query engine.

DO NOT directly interpolate user input into SQL.


Implement:

    parentheses
    AND
    OR
    NOT/negation
    eq
    neq
    in
    not-in
    contains
    greater/less comparisons
    CIDR matching
    IPv4
    IPv6


Canonical aliases:

    addr.src
    addr.dst
    port.src
    port.dst
    zone.src
    zone.dst
    user.src
    user.dst
    app
    action
    rule


Syntax errors must be clear.

Example:

    Unexpected ')' at character 42.

Never expose ClickHouse internal errors to the browser.


======================================================================
ADD LOG FILTER
======================================================================

Implement a graphical filter builder similar to PAN-OS.

Fields:

    Connector
    Attribute
    Operator
    Value
    Negate

Example:

    Connector: AND
    Attribute: Source Address
    Operator: IN
    Value: 10.150.1.161

Generates:

    ( addr.src in 10.150.1.161 )

The graphical builder and manual query box MUST use the same parser/query engine.


======================================================================
CLICK-TO-FILTER
======================================================================

Clicking table values should allow:

    Include
    Exclude

Examples:

Source IP:
    Include Source
    Exclude Source

Destination:
    Include Destination
    Exclude Destination

Application:
    Include Application
    Exclude Application

Rule:
    Include Rule
    Exclude Rule

Firewall:
    Include Device
    Exclude Device

Combine with current filter using AND/OR.


======================================================================
SAVED FILTERS
======================================================================

Support:

    Save
    Load
    Rename
    Duplicate
    Delete
    Favorite

A saved search can contain:

    name
    description
    query
    log type
    selected columns
    time range
    sort preference


Include built-ins:

    Denied Traffic
    Unknown Applications
    Internet Traffic
    DNS
    QUIC
    SSL/TLS
    Threats
    Authentication Failures


======================================================================
HOSTNAME RESOLUTION
======================================================================

Provide:

    [ ] Resolve Hostnames

matching the PAN-OS workflow.

When disabled:

    show IP only.

When enabled:

    asynchronously perform reverse DNS.

Display separate columns:

    Source
    Source Hostname

    Destination
    Destination Hostname


NEVER replace the original IP.

DNS must NEVER block:

    ingestion
    querying
    UI

Implement:

    worker pool
    timeout
    positive cache
    negative cache
    TTL
    configurable resolvers
    rate limiting
    cache clear

Store DNS enrichment separately so billions of log rows do not need rewriting.


======================================================================
EXPORT
======================================================================

Support CSV.

Options:

    Export Visible Rows
    Export All Matching Rows

Respect:

    log type
    filter
    time range
    selected columns

Large exports:

    asynchronous
    streamed to temporary disk
    progress visible
    never loaded entirely into RAM


======================================================================
LIVE VIEW
======================================================================

Auto-refresh:

    Off
    5 seconds
    10 seconds
    30 seconds
    60 seconds

Optional real-time Live mode.

Must support Pause.

Do not destroy scroll state while new records arrive.


======================================================================
RETENTION
======================================================================

Retention must be administrator-controlled.

Support:

GLOBAL:

    30
    60
    90
    180
    365
    custom

PER LOG TYPE:

Example:

    Traffic             60 days
    Threat              365 days
    URL                 90 days
    Authentication      365 days
    Configuration       365 days
    System              365 days


Use efficient ClickHouse TTL/partition behavior.

Do not use expensive row-by-row cleanup when partition/TTL mechanisms can be used.


======================================================================
STORAGE ARCHITECTURE
======================================================================

OVA DEFAULT:

Disk 1:

    80 GB
    Rocky Linux / system

Disk 2:

    1 TB logical capacity
    thin provisioned where hypervisor permits
    NebulaLog data disk


Sensitive data on the data disk must be LUKS2 encrypted.

ClickHouse firewall log storage must reside here.


Do not assume:

    1 TB = X days.

Actual retention depends upon real-world traffic.


======================================================================
AUTOMATIC DISK GROWTH
======================================================================

THIS SHOULD BE A FIRST-CLASS APPLIANCE FEATURE.

The shipped OVA may define a 1 TB data disk, but NebulaLog MUST automatically
support a larger disk presented by the hypervisor.


EXAMPLE:

OVA:

    1 TB data disk

Administrator changes disk before first boot:

    1 TB -> 5 TB

NebulaLog first boot detects:

    block device = 5 TB
    encrypted/filesystem allocation < 5 TB

and automatically grows the guest storage stack.


Implement safely:

    partition growth
        ↓
    LUKS2 resize
        ↓
    LVM PV resize
        ↓
    logical volume growth
        ↓
    XFS growth


Do not require the administrator to run shell commands.


FIRST BOOT:

Automatically consume unused capacity on the designated NebulaLog data disk.


LATER EXPANSION:

If the hypervisor expands the disk while NebulaLog is running:

    detect additional capacity

Display:

    Additional Storage Capacity Detected

    Current:       1 TB
    Available:     5 TB
    Expandable:    4 TB

    [ Expand Storage ]


Safe online expansion should be supported where possible.


======================================================================
CLOUD-INIT / GUEST TOOLS
======================================================================

Support cloud-init where useful for initial appliance customization.

Cloud-init MAY configure:

    hostname
    network
    DNS
    NTP
    initial appliance properties

However:

NebulaLog MUST NOT depend on cloud-init for normal lifecycle management.


Create dedicated systemd services such as:

    nebulalog-firstboot.service
    nebulalog-storage.service


Install/support appropriate guest integration where possible:

VMware:

    open-vm-tools

Nutanix:

    Nutanix Guest Tools where appropriate/documented

KVM/Proxmox:

    qemu-guest-agent


Guest tools should improve integration but not be required for core operation.


======================================================================
ADDITIONAL DATA DISKS
======================================================================

Support adding another disk.

Example:

    Disk 2 = 1 TB
    Disk 3 = 4 TB


Administration
  -> Storage

Detect:

    /dev/sdc
    4 TB
    Blank


Display:

    New Data Disk Detected

    [ Add to NebulaLog Storage ]


Require explicit administrative confirmation.

NebulaLog performs:

    initialize
    LUKS2 encryption
    secure key enrollment
    storage pool extension
    filesystem expansion


Never automatically consume an unknown disk.


======================================================================
STORAGE SIZING ENGINE
======================================================================

NebulaLog must learn the customer's real storage requirements.

Continuously calculate:

    Current EPS
    1-hour average EPS
    24-hour average EPS
    7-day average EPS

    Peak 1-minute EPS
    Peak 5-minute EPS
    Peak 1-hour EPS

    events/day

    actual ClickHouse bytes/event
    actual database growth/day

    disk capacity
    used
    available
    operational reserve


Calculate estimated retention for the CURRENT disk.


Also calculate required capacity for:

    30 days
    60 days
    90 days
    180 days
    365 days


Example:

    Current Capacity            1.00 TB
    Current EPS                 265
    Events / Day                22.9M
    Database Growth / Day       34 GB
    Current Estimated Retention 25 days

    30 Day Requirement          1.2 TB
    90 Day Requirement          3.6 TB
    180 Day Requirement         7.2 TB
    365 Day Requirement         14.5 TB


These are examples only.

REAL calculations MUST use measured database growth.


Maintain approximately:

    15% operational free-space reserve


Recommend sensible rounded-up capacities.


======================================================================
REFERENCE PERFORMANCE PROFILE
======================================================================

A known very active firewall produces approximately:

    265 average EPS
    22.9 million events/day


This workload MUST become a benchmark profile.

Generate realistic sanitized PAN-OS logs representing this rate.

Measure:

    ingestion CPU
    ingestion RAM
    disk writes
    ClickHouse compression
    ClickHouse bytes/event
    index overhead
    query latency
    retention operations
    CSV export
    DNS enrichment
    peak burst handling


Test:

    30-day equivalent
    90-day equivalent

through generated/imported benchmark datasets where practical.


Also benchmark at least:

    10 million records
    100 million records

and preferably:

    1 billion records


======================================================================
STORAGE SAFETY
======================================================================

Thresholds:

    70% Informational
    80% Warning
    90% Critical
    95% Emergency


Show estimated:

    Days Until Full


Default emergency policy:

Protect appliance/database integrity.

When required:

    purge oldest eligible high-volume Traffic partitions first

while attempting to preserve higher-value logs according to configured minimum
retention.


This behavior must be:

    configurable
    auditable
    clearly documented


Never allow uncontrolled logging to silently fill the disk and corrupt services.


======================================================================
STORAGE DOCUMENTATION
======================================================================

Create:

    docs/STORAGE.md
    docs/STORAGE_SIZING.md
    docs/STORAGE_EXPANSION.md


Provide exact instructions for:

    VMware vSphere
    Nutanix AHV
    Proxmox
    KVM/libvirt
    Hyper-V where validated


Document:

    thin provisioning
    thick provisioning
    expanding existing virtual disk
    adding a disk
    pre-boot disk expansion
    online expansion
    LUKS implications
    backups
    validation
    troubleshooting


The normal expansion workflow should be:

    1. Increase virtual data disk in hypervisor.
    2. NebulaLog detects added capacity.
    3. Click Expand Storage.
    4. NebulaLog completes guest-side expansion.

If capacity is enlarged prior to first boot:

    NebulaLog should automatically use all available capacity.


======================================================================
KEYCLOAK AUTHENTICATION
======================================================================

NebulaLog MUST require authentication.

Use Keycloak.

Operate Keycloak in the appropriate strict FIPS configuration.

Do not build a homemade authentication system.


SUPPORTED METHODS:

LOCAL
    Default.

ACTIVE DIRECTORY
    LDAP/LDAPS federation.

SAML 2.0
    External IdP.

OIDC
    External IdP.


======================================================================
LOCAL AUTHENTICATION
======================================================================

Local accounts are available by default.

MFA is mandatory for administrators.

Prefer requiring MFA for all local users.

Support:

    TOTP
    WebAuthn/passkeys
    recovery codes


No universal passwords.

Initial administrator is created during first boot.


Maintain at least one:

    local break-glass Administrator

External identity configuration must never accidentally eliminate all local
administrative access.


======================================================================
ACTIVE DIRECTORY
======================================================================

Support Active Directory federation using Keycloak.

Production default:

    LDAPS


Support:

    username
    UPN
    email
    user synchronization
    groups
    group-to-role mapping


Authentication flow:

    AD Username + Password
              ↓
    AD validation
              ↓
    Keycloak MFA
              ↓
    NebulaLog


This allows traditional Active Directory authentication plus NebulaLog-managed
MFA.


======================================================================
SAML
======================================================================

Support generic SAML 2.0 IdPs.

UI wizard should support:

    metadata XML import

or manual:

    Entity ID
    SSO URL
    certificate
    logout URL


Support standards-compatible providers such as:

    Microsoft Entra ID
    Okta
    AD FS
    Duo
    Ping
    generic SAML 2.0


======================================================================
OIDC
======================================================================

Support generic OpenID Connect.

Allow:

    discovery URL

or manual endpoints.


======================================================================
RBAC
======================================================================

Roles:

ADMINISTRATOR

    Full appliance/application control.

ANALYST

    Search
    export
    saved filters
    read access

VIEWER

    Search/read only.


External groups/claims can map to NebulaLog roles.


======================================================================
ROCKY LINUX
======================================================================

Use:

    Rocky Linux 9 x86_64


Minimal installation.

Do not install unnecessary desktop packages.


======================================================================
FIPS
======================================================================

FIPS mode MUST be enabled during the appliance image installation/build process,
not retrofitted after normal operation.


Verify:

    /proc/sys/crypto/fips_enabled = 1

and appropriate FIPS tooling reports enabled.


Use system crypto policy:

    FIPS


Generate appliance-specific keys/secrets only after FIPS mode is active.


IMPORTANT:

Do not falsely claim that simply enabling FIPS mode makes the entire application
"FIPS certified."

Maintain accurate documentation of:

    validated crypto modules
    module versions
    CMVP certificate mappings
    operating environment
    known exceptions


Any application cryptography must be designed to use appropriate FIPS-compatible
crypto implementations.


======================================================================
LUKS2
======================================================================

Sensitive persistent data must use LUKS2.

Never ship a universal encryption key.


Support:

    Console passphrase

and, where supported:

    TPM2 / vTPM-backed unlock

plus:

    unique recovery key


Each appliance must have unique encryption material.


======================================================================
SELINUX
======================================================================

Must operate:

    Enforcing


Do not disable SELinux to fix application issues.

Create proper policy/context configuration.

Production acceptance test fails if:

    getenforce != Enforcing


======================================================================
PODMAN
======================================================================

Use Podman/systemd Quadlets for the OVA.

Containers:

    run non-root where possible
    no --privileged
    drop unnecessary capabilities
    no container socket exposure
    read-only roots where appropriate
    SELinux labels
    no public database exposure


Docker Compose MAY be provided for developer/community deployments.

The production OVA is Podman-based.


======================================================================
FIREWALL
======================================================================

Use firewalld.

Default inbound:

    DENY


Required:

    TCP/443


Optional as configured:

    UDP/514
    TCP/514
    TCP/6514


SSH:

    disabled by default


If enabled:

    no root login
    key-based preferred
    FIPS crypto policy
    auditing


ClickHouse/PostgreSQL:

    NEVER exposed publicly by default.


======================================================================
COMPLIANCE BASELINE SELECTION
======================================================================

FIPS, LUKS, SELinux, auditing, firewalling, and minimum host hardening are always
enabled.

During first boot:

Select Security Baseline:

    ○ CIS Rocky Linux 9 Level 2

    ● Unified Hardened — Recommended
      CIS Level 2 + DISA STIG

    ○ DISA STIG


UNIFIED behavior:

Same requirement:
    apply once.

Compatible but different:
    use stricter setting.

Direct conflict:
    use documented NebulaLog security precedence,
    generally favoring DISA/STIG.

Application incompatibility:
    create explicit exception.

Never silently skip controls.


======================================================================
OPENSCAP / COMPLIANCE
======================================================================

Use:

    OpenSCAP
    SCAP Security Guide


Provide:

    nebulalog compliance status
    nebulalog compliance scan


UI:

Administration
  -> Security
     -> Compliance


Show:

    FIPS status
    LUKS status
    SELinux status
    selected baseline
    CIS assessment
    STIG assessment
    exceptions
    last assessment


Do not redistribute benchmark content in violation of licensing.

Use accurate terms such as:

    CIS Level 2 aligned
    DISA STIG hardened/aligned

unless formal certification supports stronger claims.


======================================================================
AUDITING
======================================================================

Enable auditd.

Audit:

    logins
    sudo
    account changes
    service changes
    package changes
    SELinux changes
    FIPS changes
    LUKS operations
    certificates
    configuration changes
    retention changes
    disk expansion
    updates
    external auth changes


NebulaLog administrative actions also require application-level auditing.


======================================================================
AUTOMATIC APPLIANCE MANAGEMENT
======================================================================

NebulaLog is an APPLIANCE.

A deployed appliance must not require CI/CD.

Do not require:

    Jenkins
    GitHub Actions
    GitLab CI
    Kubernetes
    Argo
    external configuration management


The appliance maintains itself.


======================================================================
UPDATE MANAGER
======================================================================

Implement:

    nebulalog update status
    nebulalog update check
    nebulalog update install
    nebulalog update history
    nebulalog update rollback


UI:

Administration
  -> System
     -> Updates


Manage:

    Rocky Linux
    kernel
    NebulaLog
    Keycloak
    ClickHouse
    PostgreSQL
    SCAP content
    NebulaLog security baseline content


======================================================================
AUTOMATIC UPDATE DEFAULTS
======================================================================

Enabled by default.

Check:

    Daily


OS:

    Rocky security updates automatic
    Rocky supported minor updates automatic
    kernel updates automatic


APPLICATION:

    NebulaLog Stable releases automatic


KEYCLOAK:

    NebulaLog-managed version


CLICKHOUSE:

    NebulaLog-managed version


POSTGRESQL:

    security/minor updates automatically
    major upgrades controlled by NebulaLog


COMPLIANCE CONTENT:

    automatic


======================================================================
CLICKHOUSE UPDATE POLICY
======================================================================

ClickHouse MUST NOT independently jump to arbitrary releases.

NebulaLog controls supported ClickHouse versions.

Prefer:

    stable/LTS appropriate release family


NebulaLog release manifest specifies:

    supported version family
    tested minimum
    tested maximum
    approved upgrade path


Safe patch updates can occur automatically.

Major/family changes occur only when explicitly approved by NebulaLog.


======================================================================
KEYCLOAK UPDATE POLICY
======================================================================

Keycloak version is controlled by NebulaLog.

Before committing a Keycloak update test:

    startup
    FIPS mode
    local authentication
    MFA
    AD
    SAML
    OIDC
    role mapping


======================================================================
MAINTENANCE WINDOW
======================================================================

First boot asks:

    Maintenance Day
    Start Time
    End Time
    Time Zone


Default:

    Sunday
    03:00–05:00 local time


Automatically install kernels.

If reboot required:

    reboot during maintenance window.


Retain:

    current kernel
    previous two kernels


======================================================================
SIGNED UPDATES
======================================================================

NebulaLog application releases must be cryptographically signed.

The appliance includes the trusted release verification public key.

Installing an update requires:

    valid signature
    valid cryptographic hash


A compromised download source alone must not be enough to compromise appliances.


======================================================================
UPDATE TRANSACTION
======================================================================

Before update:

    verify signature
    verify hashes
    verify disk space
    verify database health
    backup PostgreSQL
    backup configuration
    record component versions
    prepare ClickHouse
    buffer/drain ingestion if required


Update.


After:

    verify API
    verify Web
    verify ClickHouse
    verify PostgreSQL
    verify Keycloak
    verify local auth
    verify ingestion
    verify FIPS
    verify SELinux
    verify LUKS
    verify firewall
    run compliance assessment


On failure:

    rollback application/components where technically possible.

Never leave the appliance silently broken.


======================================================================
FIRST BOOT
======================================================================

First boot workflow:

1. Verify FIPS.
2. Verify SELinux.
3. Detect actual data-disk capacity.
4. Automatically grow data disk to consume presented capacity.
5. Initialize/verify LUKS2.
6. Generate unique secrets.
7. Create administrator.
8. Require MFA enrollment.
9. Generate recovery codes.
10. Configure hostname.
11. Configure network.
12. Configure DNS.
13. Configure NTP.
14. Select CIS/STIG security baseline.
15. Configure maintenance window.
16. Configure initial retention.
17. Configure optional AD/SAML/OIDC.
18. Show firewall forwarding setup.
19. Verify Syslog receipt.
20. Run compliance scan.


======================================================================
FIREWALL SETUP README
======================================================================

Create:

    docs/FIREWALL_SETUP.md


Extremely clear instructions are mandatory.


PAN-OS:

Device
  -> Server Profiles
     -> Syslog


Create:

    NebulaLog


Server:

    <NEBULALOG-IP>


Support:

    UDP 514
    TCP 514
    TLS 6514


NebulaLog should support standard PAN-OS Syslog output without requiring a
custom message format.


DATA PLANE:

Objects
  -> Log Forwarding

Create:

    NebulaLog


Configure supported categories.


SECURITY RULES:

Policies
  -> Security

Edit applicable rules.

Actions:

    Log Forwarding = NebulaLog


Recommend:

    Log at Session End


Explain:

Creating a Syslog Server Profile alone DOES NOT cause Traffic logs to forward.


MANAGEMENT PLANE:

Device
  -> Log Settings


Configure relevant:

    System
    Configuration
    User-ID
    HIP
    GlobalProtect
    etc.


Then:

    COMMIT


VERIFY:

Administration
  -> Firewalls

then:

Logs
  -> Traffic


======================================================================
SYSLOG DIAGNOSTICS
======================================================================

Administration
  -> Diagnostics
     -> Syslog


Show:

    UDP 514     Listening
    TCP 514     Listening
    TLS 6514    Listening


LAST RECEIVED:

    Time
    Sender
    Firewall
    Serial
    Log Type
    Parse Status


Allow:

    View Raw Message


Documentation must include:

    tcpdump
    connectivity checks
    TLS troubleshooting
    PAN-OS service routes
    missing forwarding profiles
    Log at Session End
    commit status


======================================================================
HEALTH
======================================================================

Provide:

    GET /api/health

and:

    GET /api/metrics


Expose:

    application status
    database status
    ingestion
    storage
    DNS
    auth
    update service


Prometheus-compatible metrics where practical.


======================================================================
BACKUP / RESTORE
======================================================================

Provide:

    nebulalog backup
    nebulalog restore


Backup:

    PostgreSQL metadata
    NebulaLog configuration
    authentication configuration
    certificates/secrets where appropriate
    security baseline
    optional ClickHouse data


Document the distinction between:

    configuration backup
    full log-data backup


Do not assume customers will want multi-terabyte ClickHouse backups copied as
part of every configuration backup.


======================================================================
UI DESIGN
======================================================================

Dense.

Technical.

Fast.

Professional.

Designed for:

    network engineers
    SOC analysts
    firewall administrators


Avoid:

    giant cards
    massive whitespace
    consumer SaaS design
    excessive animations


The log table is the product.


======================================================================
DOCUMENTATION
======================================================================

Repository:

README.md
LICENSE
CONTRIBUTING.md
CODE_OF_CONDUCT.md
SECURITY.md
CHANGELOG.md


docs/

    ARCHITECTURE.md
    FIREWALL_SETUP.md
    INSTALL_OVA.md
    INSTALL_DOCKER.md
    STORAGE.md
    STORAGE_SIZING.md
    STORAGE_EXPANSION.md
    SYSLOG.md
    QUERY_LANGUAGE.md
    CLICKHOUSE.md
    POSTGRESQL.md
    RETENTION.md
    BACKUP_RESTORE.md
    TLS.md
    TROUBLESHOOTING.md
    DEVELOPMENT.md
    SECURITY_HARDENING.md
    FIPS.md
    LUKS.md
    CIS.md
    DISA_STIG.md
    COMPLIANCE.md
    SELINUX.md
    AUTHENTICATION.md
    ACTIVE_DIRECTORY.md
    SAML.md
    UPDATES.md


======================================================================
README INTRODUCTION
======================================================================

Use substantially:

# NebulaLog

NebulaLog is a fast, local-first, open-source log collector and explorer for
PAN-OS firewalls.

Forward firewall logs to NebulaLog using Syslog and get a familiar,
PAN-OS-inspired interface for centralized searching, filtering, retention, and
export without requiring cloud logging services or a traditional SIEM.


Include trademark disclaimer:

NebulaLog is an independent open-source project and is not affiliated with,
endorsed by, or sponsored by Palo Alto Networks. Palo Alto Networks, PAN-OS,
and related names are trademarks of their respective owner.


======================================================================
PERFORMANCE TARGETS
======================================================================

At minimum validate:

    10M records
    100M records


Prefer:

    1B records


Reference production workload:

    265 average EPS
    ~22.9 million records/day


Queries to benchmark:

    source IP
    destination IP
    CIDR
    application
    rule
    action
    firewall
    port
    source + destination
    time range
    denied traffic


Targets on appropriately sized hardware:

    recent common query:
        typically < 1 second

    24 hours:
        typically < 2 seconds

    common 7-day filtered query:
        typically < 5 seconds


Document hardware and dataset for every benchmark.


======================================================================
TESTING
======================================================================

Unit tests:

    PAN parser
    Syslog framing
    UDP
    TCP
    TLS
    query lexer
    query parser
    AST
    query compiler
    IPv4
    IPv6
    CIDR
    DNS
    retention
    CSV


Integration:

    firewall-like event
        -> listener
        -> parser
        -> ClickHouse
        -> API
        -> query
        -> UI


Authentication:

    local
    MFA
    AD test environment
    SAML/OIDC test providers where practical


Storage:

    1 TB-presented equivalent
    simulated enlarged disk
    auto-grow
    added disk
    LUKS resize
    filesystem resize


Security:

    FIPS
    SELinux
    compliance profile
    firewall
    audit


Updates:

    app upgrade
    rollback
    kernel update
    reboot
    Keycloak upgrade
    ClickHouse supported upgrade


======================================================================
VERSION 1 ACCEPTANCE CRITERIA
======================================================================

Do not call version 1 complete until:

[ ] OVA builds successfully
[ ] Rocky Linux boots
[ ] FIPS enabled
[ ] LUKS2 enabled
[ ] SELinux Enforcing
[ ] CIS baseline selectable
[ ] Unified CIS+STIG selectable
[ ] DISA STIG baseline selectable
[ ] Keycloak working
[ ] local login working
[ ] MFA working
[ ] AD federation working
[ ] AD + Keycloak MFA working
[ ] SAML working
[ ] OIDC working
[ ] PostgreSQL healthy
[ ] ClickHouse healthy

[ ] 1 TB thin data disk deployment works
[ ] larger pre-boot virtual disk automatically expands
[ ] post-deployment disk expansion works
[ ] additional-disk workflow works
[ ] LUKS remains valid after expansion
[ ] storage sizing calculations work
[ ] estimated retention works

[ ] UDP Syslog works
[ ] TCP Syslog works
[ ] TLS Syslog works
[ ] multiple firewalls identified
[ ] Traffic parsed
[ ] Threat parsed
[ ] URL parsed
[ ] supported management logs parsed
[ ] malformed logs retained

[ ] Traffic viewer works
[ ] other log views work
[ ] Unified works
[ ] column customization works
[ ] PAN-OS filter parser works
[ ] CIDR works
[ ] nested Boolean expressions work
[ ] Add Log Filter works
[ ] click-to-filter works
[ ] saved filters work
[ ] hostname resolution works
[ ] CSV export works

[ ] retention configurable
[ ] per-log-type retention works
[ ] disk warnings work
[ ] emergency disk policy works

[ ] 265 EPS sustained workload passes
[ ] bursts materially above 265 EPS pass
[ ] 100M-event benchmark passes
[ ] query benchmarks documented

[ ] automatic Rocky updates work
[ ] kernel update/reboot works
[ ] automatic NebulaLog update works
[ ] ClickHouse managed upgrade works
[ ] Keycloak managed upgrade works
[ ] signed-update validation works
[ ] post-update security checks work

[ ] backup works
[ ] restore works
[ ] documentation complete
[ ] firewall setup instructions validated


======================================================================
IMPLEMENTATION ORDER
======================================================================

PHASE 1

    architecture
    Rocky appliance build
    Podman
    PostgreSQL
    ClickHouse
    basic Syslog ingestion
    Traffic parser


PHASE 2

    Traffic viewer
    PAN-OS query parser
    graphical filters
    saved filters
    columns
    CSV


PHASE 3

    additional log types
    Unified
    DNS resolution
    firewall inventory


PHASE 4

    Keycloak
    local MFA
    AD
    SAML
    OIDC
    RBAC


PHASE 5

    FIPS
    LUKS
    SELinux
    CIS/STIG profiles
    auditing
    compliance UI


PHASE 6

    OVA
    first boot
    automatic disk growth
    additional disk management
    storage sizing
    retention engine


PHASE 7

    appliance updater
    OS/kernel updates
    ClickHouse lifecycle
    Keycloak lifecycle
    signed application updates
    rollback


PHASE 8

    benchmarks
    hardening
    documentation
    release candidate


======================================================================
DEVELOPMENT METHOD
======================================================================

Before coding:

1. Read this entire specification.
2. Inspect all provided screenshots.
3. Research current official PAN-OS documentation.
4. Research supported Rocky Linux security/FIPS mechanisms.
5. Research current CIS Rocky Linux 9 guidance.
6. Research current RHEL 9 DISA STIG/SCAP guidance.
7. Research current Keycloak FIPS support.
8. Research ClickHouse production tuning.
9. Document architecture decisions.
10. Produce the implementation milestone plan.


Then execute the plan.


After every major milestone:

    build
    run automated tests
    start the actual application
    inspect logs
    test the UI
    test persistence
    test failure conditions
    fix defects


DO NOT:

    claim something works without testing it
    leave core features as TODOs
    replace functionality with mock screens
    silently weaken security controls to make development easier


If implementation decisions differ from this specification:

    document the reasoning in an ADR
    choose the simpler/more secure/reliable approach
    do not materially change product intent without documenting it


======================================================================
FINAL PRODUCT EXPECTATION
======================================================================

The intended administrator experience is:

    Download NebulaLog OVA
        ↓
    Deploy
        ↓
    Optionally enlarge 1 TB data disk before boot
        ↓
    Boot
        ↓
    NebulaLog automatically consumes available disk capacity
        ↓
    Create Administrator + MFA
        ↓
    Choose CIS / Unified / STIG
        ↓
    Configure networking/authentication
        ↓
    Point PAN-OS Syslog to NebulaLog
        ↓
    Attach Log Forwarding profile
        ↓
    Commit firewall
        ↓
    Logs appear
        ↓
    Search immediately


After deployment, NebulaLog should largely manage itself:

    OS security updates
    kernel updates
    application updates
    supported database updates
    compliance checks
    disk utilization monitoring
    retention
    security status


The administrator should not need to be:

    a Linux administrator
    a ClickHouse administrator
    a PostgreSQL administrator
    a Keycloak administrator


NebulaLog owns those details.


The product succeeds if a firewall administrator can deploy it and think:

    "This gives me the useful parts of PAN-OS Monitor > Logs,
     except it is centralized, fast, encrypted, hardened,
     expandable, and actually retains my logs."
