# TLS

The production appliance should expose the Web/API only through TCP 443 with a unique appliance certificate. Bootstrap must show its SHA-256 certificate fingerprint on the trusted hypervisor console; replace it with an organization-trusted certificate after setup. No shared certificate private key ships in the image.

The production API Quadlet binds HTTP only to host loopback for a qualified HTTPS edge. The edge configuration is an appliance integration gate, not permission to expose HTTP publicly. Keycloak hostname, issuer and client redirects must agree on the canonical HTTPS origin. Do not accept arbitrary redirect URLs.

PAN-OS TLS Syslog uses TCP 6514 by default. Configure the collector certificate/key through the application's supported environment and mount them read-only from encrypted persistence. Validate certificate chain, expiry, SAN/name, firewall trust configuration and TLS protocol compatibility. Source allowlisting or client certificates add authentication when supported. Encrypted transport without a trusted server identity is insufficient.

Use TLS 1.2/1.3 and algorithms accepted by the qualified FIPS modules. Strict FIPS policies can reject older TLS 1.2 peers missing Extended Master Secret; investigate interoperability without lowering the entire host policy. LDAPS, external OIDC and SAML signing/TLS have separate trust stores and renewal requirements.

Test actual PAN-OS forwarding, certificate rotation, expired/untrusted certificate rejection and reconnect/spool behavior. A TCP handshake alone does not validate encrypted Syslog receipt. Never include private keys in diagnostic bundles, logs or source control.
