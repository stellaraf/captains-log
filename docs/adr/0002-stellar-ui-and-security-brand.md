# ADR0002: Stellar application patterns with security branding

Accepted2026-09-07 following the user's supplied logos, Security Brand Standards
HTML and Stellar-App-UI-Standards repository.

The application standard at commit43cb8227e749359ddd00fdbe5d38946b5b4a8f28 governs
operational hierarchy and behavior: flat surfaces, semantic tokens, native
resource routes, accessible controls, honest state, theme/density preferences and
comparable tables. The Security Brand Standards supply the Stellar identity,
Open Sans/Fira Code typography and semantic security palette.

The security document's animated heroes, decorative gradients and dark-only
collateral rule are marketing treatments. They do not override the more specific
application guide's working-screen rules. Operational screens offer Light, Dark
and System, retain quiet backgrounds, and reserve alert color for meaningful
states. Logos preserve the supplied artwork and proportions.

NebulaLog's primary task is engineering log analysis. Compact density is a
reasonable domain default, with an accessible comfortable option. Density must
adjust virtualization geometry consistently and never shrink touch targets.
The security dark palette is adapted through semantic roles rather than literal
low-opacity marketing copy colors; contrast is measured in the actual UI.

Event details and firewall records receive stable routes. Saved filters, search
scope and pagination context survive navigation. The existing real collector,
PostgreSQL metadata, ClickHouse queries, Keycloak authentication and server-side
role boundaries remain the source of data and authority.

Okta and Microsoft Entra ID are the primary SAML setup guides. The in-app help
uses appliance-derived values and explains provider setup, explicit role mapping,
MFA, validation, certificate rollover and recovery. Documentation is not a claim
that an external tenant has been configured or tested.
