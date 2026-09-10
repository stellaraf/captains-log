# Stellar Captain’s Log login theme

Theme name: **nebulalog** (retained for compatibility). Parent: **keycloak.v2**, verified directly from the running Keycloak **26.3.3** distribution's `org.keycloak.keycloak-themes-26.3.3.jar`. This theme styles inherited login, password, OTP, recovery, and provider controls without changing authentication flows, endpoints, scripts, hidden fields, or submission behavior.

Mount this directory read-only at `/opt/keycloak/themes/nebulalog`, then set the intended realm's `loginTheme` to `nebulalog`. Set the realm's plain `displayName` and `displayNameHtml` to `Captain’s Log`. Existing realm imports do not necessarily update an already-created realm: verify the actual realm setting after deployment. Keep the standard parent resources available in the Keycloak distribution. Do not replace the entire `/opt/keycloak/themes` directory with an incomplete bundle.

```yaml
volumes:
  - ./deploy/keycloak/themes/nebulalog:/opt/keycloak/themes/nebulalog:ro
```

The theme uses the application's semantic palette and locally bundled Open Sans variable fonts. Supplied Stellar PNGs are copied unchanged from `web/public/brand`; no external font or image request is required. The Open Sans license is included under `login/resources/licenses/`. Light mode is deliberate and independent of the application's per-user display setting. Keycloak's 26.3.3 parent favicon remains inherited; the unchanged Stellar icon is available for future version-supported favicon customization without replacing the security-sensitive common layout.

The only template override is `login-config-totp.ftl`, copied from the exact deployed `keycloak.v2` parent. Two existing `label for="form-vertical-name"` values referred to no input. They now point to `totp` and `userLabel`, respectively. Those two attribute values are the complete difference. All QR/manual enrollment options, hidden values, required actions, form targets, validation, and session controls are inherited verbatim. Rebase this override against the deployed parent whenever upgrading Keycloak. Parent source is Apache-2.0 licensed.

Before considering an upgrade verified, compare the template against the installed parent and exercise password login, OTP login, OTP enrollment, error presentation, keyboard focus, narrow-screen layout, and successful redirect back to the application. Enrollment screenshots must mask the QR image, manual secret, hidden enrollment values and entered codes. Theme installation and selecting a realm theme are presentation changes; they do not verify external federation, MFA policy, FIPS, or a completed login by themselves.

The parent supports inherited styles and resources through `theme.properties`; parent CSS loads first and the application sheet (`nebulalog.css`) loads last. Production should retain theme caching. Development cache changes and Keycloak restarts must be coordinated with active login tests. See the [official theme guide](https://www.keycloak.org/ui-customization/themes) and [versioned parent properties](https://github.com/keycloak/keycloak/blob/26.3.3/themes/src/main/resources/theme/keycloak.v2/login/theme.properties).

Validation at authoring: exact parent inspected, logo/icon copies checked byte-for-byte, every local font reference resolves, and OTP template compared to the parent with exactly the two label associations changed. Deployed login/OTP visual checks are recorded below after coordination.

Static contrast checks: text/white 18.23:1, muted text/white 5.18:1, primary button text 9.67:1, error text/tinted surface 5.86:1, input border/white 3.21:1, and focus indicator/white 9.67:1. Interactive targets have a minimum 44px height and controls retain visible keyboard focus. Actual rendered semantics and overflow still require the deployment checks.

Deployed validation on 2026-09-07: fresh local password and OTP login passed against Keycloak 26.3.3 with this theme; an invalid OTP was rejected and the automated administrator session was refreshed through the normal flow. Desktop (1440px) and mobile (375px) password screenshots were inspected. The desktop card is 460px wide; mobile card is 343px with no horizontal page overflow. The parent's hidden reset-login tooltip initially extended beyond the mobile viewport; it is now anchored within the card and its width is bounded without clipping the form. The parent's desktop side padding was removed to preserve the intended card width. Final screenshots are `.local/login-desktop.png` and `.local/login-mobile.png`; OTP captures mask the entered code. The two-label enrollment correction was verified against the exact parent source, but a new user's enrollment was not repeated during this visual pass.
