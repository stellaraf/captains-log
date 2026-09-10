# Captain’s Log name and compatibility

The product was renamed from NebulaLog to **Captain’s Log** on September 9, 2026. The repository slug and Go module are `captains-log` and `github.com/stellaraf/captains-log`. Stellar logos, visual styling and the tagline “Fast, local-first PAN-OS log collection and search.” remain in use.

The name appears in the browser, login display, first-boot console, user-facing application messages, documentation and future OVA product descriptions. Files exported through the browser use the `captains-log` prefix.

Existing installations retain their technical identifiers: the `nebulalog` command, Python package, service and container names, database names, Keycloak realm/client/flow IDs, API paths, filesystem paths, environment variables, signed metadata identifiers and browser preference keys. These names are compatibility contracts. Renaming the product does not create a new authentication realm, reset MFA, migrate data or invalidate saved preferences. Existing IdP group examples such as `NebulaLog-Administrators` continue to describe literal configured group values; administrators should use their own existing mappings.

Historical validation reports, original firewall records, captured source archives and private frozen candidates retain the name under which they were recorded. The original specification is preserved with a name-update note. Candidate v8 was frozen before this rename and is not a Captain’s Log release artifact; the renamed appliance needs a new capture and qualification.

At the rename checkpoint, this local checkout has no Git remote and an accessible `stellaraf/nebulalog` repository has not been found. The intended GitHub destination is `stellaraf/captains-log`; creation or a remote rename is recorded separately after the existing repository is identified. A local module-name change is not evidence of a GitHub rename or publication.
