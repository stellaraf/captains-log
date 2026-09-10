# Web application

Captain’s Log’s browser application is a React/TypeScript client of the authenticated application API. It contains no sample-record or simulated-health fallback. Empty, unavailable and unverified states are rendered from actual API results.

## Development

Run the real services using `docs/DEVELOPMENT.md`, then:

```sh
cd web
npm ci
npm run build
npm test
```

The production output is `web/dist`. Vite development mode proxies `/api` to the local Go API. The application starts by reading `/api/config`, then initializes the official Keycloak adapter with the standard authorization-code flow, S256 PKCE and required login. Access and refresh tokens stay in memory. The API performs independent signature, issuer, audience, expiry and role checks.

## Explorer behavior

Each category has a URL under `/logs/`; `/logs/parsing` exposes retained malformed/unrecognized messages. The query bar, graphical builder and include/exclude actions all submit to the same server-side compiler. Failed syntax validation does not issue a search. Search results retain the time bounds of their successful query when loading cursor pages or creating an export.

The table uses a bounded DOM window over cursor-loaded rows, sticky column headers, horizontal scrolling, keyboard-accessible resizing and per-category PostgreSQL layouts. The column dialog supports visibility and order. Default Traffic columns follow the specification. Hostnames remain separate from original IP addresses; only the visible row window requests DNS enrichment, with no more than 200 addresses per request. DNS failures do not prevent log search.

Auto-refresh supports off/5/10/30/60 seconds and Pause. It waits while the operator has scrolled into older rows rather than replacing those rows. A control returns to the latest records. Saved-filter CRUD, duplication, favorites and load actions persist through the API. Analysts can save and export; viewers receive read-only controls, backed by server enforcement.

Loaded-row CSV exports are intentionally bounded to the rows loaded by the operator. Large matching exports run as disk-backed server jobs. A short-lived, single-use download capability is requested only after completion, then handed to the browser's native download manager. The UI never buffers a large matching export into a Blob. Formula-like values in CSV are neutralized. A background export uses the successful query snapshot; it includes original IP columns instead of the transient DNS cache.

## Browser verification

Install a Playwright browser or set `NEBULALOG_E2E_CHANNEL=chrome` to use an installed Chrome. Browser tests require the real running API and Keycloak. They do not intercept API routes or bypass authentication.

```sh
NEBULALOG_E2E_URL=http://127.0.0.1:18080 \
NEBULALOG_E2E_STORAGE_STATE=/absolute/private/browser-state.json \
NEBULALOG_E2E_CHANNEL=chrome npm run test:e2e
```

The session-state file must come from a real MFA-enrolled identity. Keep test credentials, OTP secrets, session cookies, access tokens and traces outside tracked source and private to their owner. Test traces can include authenticated HTTP requests. The repository ignores `.local`, `test-results` and `playwright-report`.

The suite verifies the anonymous login gate, saved-filter creation/reload/load/deletion, graphical filter submission, layout persistence across reload, Pause/Resume and observed diagnostic/storage/security surfaces. Tests restore the layout checkbox and delete their temporary saved filters on a successful run.

## Historical baseline evidence recorded 2026-09-07

Before the Docker deployment and Stellar redesign, the local native application at `127.0.0.1:18080`, backed by real PostgreSQL, ClickHouse and Keycloak, passed a production frontend build, 16 focused utility tests, and four browser tests. A local administrator completed required SHA-256 TOTP enrollment and a separate new browser session completed password-plus-TOTP login. A native matching CSV download contained 517 received log records plus its header (100,025 bytes at capture). These counts describe one test snapshot, not a performance benchmark.

This is application evidence, not Rocky appliance/FIPS certification, a 100M-row benchmark, or acceptance of AD, external SAML/OIDC, recovery codes or WebAuthn. Those gates remain separate in `ACCEPTANCE.md`.

After the application moved to Docker, browser verification also passed exact raw-payload detail matching, source click-to-filter, a CIDR search against real retained rows, the asynchronous DNS worker endpoint, 200-to-400 cursor pagination, and discovered firewall inventory with no browser page errors. Saved ascending/descending sort order round-tripped through PostgreSQL and restored in the UI. A second native export contained 1,755 received records plus the header (339,969 bytes). Temporary saved test filters were deleted and the original sort layout restored.

## Stellar application design

The UI adopts the supplied Stellar App UI Standard (`https://github.com/stellaraf/Stellar-App-UI-Standards`) for flat operational surfaces, explicit account/context navigation, meaningful resource identity, first-class detail pages, semantic light/dark themes and accessible native controls. The supplied security identity determines the deep navy dark canvas, restrained blue/purple accent and teal technical text. Gradients are confined to the original supplied logo pixels; operational controls and surfaces remain flat.

`web/public/brand` contains the unchanged user-supplied Stellar icon and no-tagline wordmark. Open Sans and Fira Code are bundled from pinned Fontsource packages and served by the appliance; no cloud font request is required. Their OFL licenses ship under `public/licenses`. The Stellar brand assets remain their owner's identity assets and are not re-licensed by the font licenses.

Light, Dark and System appearance plus Compact/Comfortable density and navigation collapse persist per authenticated user in PostgreSQL via `/api/preferences`. Local storage contains only the appearance cache needed before the authenticated read; an external same-origin `appearance.js` applies it before paint under the strict script CSP. System follows the operating system. Compact is the deliberate default adaptation for the specified dense log-analysis workflow, with 32px table rows; Comfortable uses 44px rows. Coarse pointers always get at least 44px interactive targets and matching table virtualization geometry.

Each event opens a native-link route at `/logs/{category}/events/{id}` with the exact event receive time and actual event type. The bounded authenticated detail endpoint supports refresh and opening in another tab. The return address preserves query, time, columns and sorting; a bounded in-memory cache preserves loaded cursor pages and scroll position within the current tab. It never stores event payloads in local/session storage. Firewall links open `/administration/firewalls/{serial}` for observed identity/activity and authorized inventory edits.

Authentication includes separate Entra ID and Okta setup guides, current-derived SP entity/ACS/metadata URLs, immutable principal and exact group mapping instructions, mandatory broker OTP, certificate rollover, recovery and troubleshooting. The configuration tab uses admin-only API operations to read actual provider state, upload/paste trusted metadata, preview issuer/endpoints/certificates/group mappings, save disabled or explicitly enable, and run configuration checks. A save or configuration check never claims that an external SAML login or upstream MFA was tested. Unsupported management remains explicit while the guides stay usable.

The branded UI's first real Docker review passed 32px compact / 44px comfortable geometry, preference reload, all 40 page/theme/viewport combinations at 320/390/768/1440px without page-level horizontal overflow, and 20 computed text/background contrast pairs (minimum 4.59:1). Full event pages passed direct reload and exact raw-payload matching, with click-to-filter, CIDR, DNS and 200-to-400 pagination preserved; the four authenticated/anonymous browser regression tests also passed. Initial screenshots found unreadable copied logo file permissions; source copies were normalized to 0644 without changing bytes. The final deployment rerun confirmed the corrected logo assets.

The provider UI was exercised against the real Keycloak management API using an explicitly identified, disabled test fixture: invalid XML rejection; exact issuer/SSO/certificate preview; Save disabled provider; reload with persisted exact group mappings; and configuration-only checks. The fixture did not contact or enable an external IdP, and `external_login_tested` remained false. Actual Okta/Entra tenant sign-in and upstream MFA remain acceptance gates.

### Final branded Docker verification

The rebuilt Docker application serves both original logo files successfully and loads its bundled fonts without cloud requests or script-CSP errors. The final 40-case review used loaded, real content on the log explorer, firewall inventory, storage, authentication guide and provider editor in both themes at 320/390/768/1440px; all passed page-overflow checks. Theme/density persistence, Entra/Okta guide switching, firewall resource reload, and actual 32px/44px desktop row geometry passed. The final computed contrast sample contained 20 text/background pairs with a minimum ratio of 4.59:1. This sampling supports those rendered pairs, not a comprehensive accessibility certification.

Dedicated event navigation passed reload with exact raw-message equality; back navigation preserved the same 400 loaded records, 900px table scroll position and paused refresh state. Source filtering, CIDR queries, DNS worker/columns, cursor paging and firewall discovery passed again with no page errors. Compact mode exposes 18 fully visible rows in the tested 1560×1000 viewport with the complete toolbar and ingestion strip; no columns or controls were removed to inflate that count. A separate touch-device test found a one-pixel border/target mismatch; the coarse-pointer separator was changed to an inset line, yielding the intended 44px row / 48px header geometry. The final deployed smoke check confirmed exact 44px touch rows / 48px headers with no page overflow.

The independent current-provider enable review was opened and cancelled: no PATCH request was sent, and the explicitly identified Okta test fixture remained disabled. The actual enable/disable lifecycle and fail-closed behavior are enforced and tested by the backend; no external IdP was enabled for browser verification. Root removed the disabled fixture after its checks; the final browser/API read confirmed that both Okta and Entra are unconfigured.

The Stellar Keycloak theme was verified in fresh browser sessions: local password followed by required OTP succeeded, an invalid OTP was rejected, and the automated test session was renewed. Password and OTP pages fit a 375px viewport after correcting the hidden reset-login tooltip; the final desktop card width is 460px. Screenshots of OTP surfaces mask the code field. The new human operator account was not enrolled by automation. External Okta/Entra login, upstream MFA assurance, enrollment/recovery for the human account, and Rocky appliance/FIPS qualification remain separate acceptance work.

The final deployed runtime smoke passed real event display and detail reload, original-logo decoding, provider-management availability with both test-free providers unconfigured, and exact touch virtualization geometry. The authenticated browser reported no page errors, and all four real browser regression tests plus the 16 utility tests passed for the final frontend source.
