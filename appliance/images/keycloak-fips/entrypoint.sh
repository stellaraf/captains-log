#!/bin/bash
set -euo pipefail
case "${1:-start}" in
  --help|--version|show-config) ;;
  start|bootstrap-admin|import|export)
    if [[ ! -r /proc/sys/crypto/fips_enabled ]] || [[ "$(</proc/sys/crypto/fips_enabled)" != 1 ]]; then
      printf '%s\n' 'Captain’s Log Keycloak refused: an actual FIPS-enabled host kernel is required.' >&2
      exit 78
    fi
    if [[ "${KC_FIPS_MODE:-strict}" != strict ]]; then
      printf '%s\n' 'Captain’s Log Keycloak refused: strict FIPS mode is mandatory.' >&2
      exit 78
    fi
    providers="$(java -XshowSettings:security:providers -version 2>&1)" || {
      printf '%s\n' 'Captain’s Log Keycloak refused: JVM security provider inspection failed.' >&2
      exit 78
    }
    if [[ "$providers" != *'Provider name: SunPKCS11-NSS-FIPS'* ]] || [[ "$providers" != *'Provider name: XMLDSig'* ]]; then
      printf '%s\n' 'Captain’s Log Keycloak refused: the FIPS JVM and SAML XMLDSig providers are required.' >&2
      exit 78
    fi
    for arg in "$@"; do
      case "$arg" in
        --fips-mode|--fips-mode=*|--features|--features=*|--features-disabled|--features-disabled=*)
          printf '%s\n' 'Captain’s Log Keycloak refused: image security features cannot be overridden.' >&2
          exit 78 ;;
      esac
    done
    export KC_FIPS_MODE=strict KC_FEATURES=fips,recovery-codes,passkeys
    unset KC_FEATURES_DISABLED
    ;;
  *) printf '%s\n' 'Captain’s Log Keycloak refused: command is not supported by the sealed image.' >&2; exit 78 ;;
esac
exec /opt/keycloak/bin/kc.sh "$@"
