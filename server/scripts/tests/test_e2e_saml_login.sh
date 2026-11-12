#!/usr/bin/env bash
# E2E: SAML 2.0 SP-initiated login (RFC-009 9e).
# Verifies the happy-path Login redirect (config → AuthnRequest → IdP redirect)
# and the safe error-redirects, against the running stack. Full ACS assertion
# validation is covered by unit tests (signed-assertion parsing needs a real IdP
# for interop acceptance).
set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_e2e_common.sh
. ./_e2e_common.sh

e2e_init "saml sp login (RFC-009 9e)"
e2e_bootstrap_auth
SLUG="$(extract_json "$BODY" '.tenant_slug')"
if [ -z "$SLUG" ] || [ "$SLUG" = "null" ]; then
  print_failure "capture tenant slug" "create-first-team did not return tenant_slug"
  e2e_finish
fi
print_info "tenant slug=$SLUG"

# A throwaway self-signed cert to act as the IdP signing certificate.
CERT="$(openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -subj '/CN=e2e-idp' -days 1 2>/dev/null)"
if [ -z "$CERT" ]; then
  print_failure "generate idp cert" "openssl produced no certificate"
  e2e_finish
fi

# Configure + enable SAML for this tenant (admin).
CFG="$(jq -n --arg c "$CERT" '{idp_entity_id:"https://idp.e2e.test/entity", idp_sso_url:"https://idp.e2e.test/sso", idp_certificate:$c, allowed_domains:[], default_role:"member", auto_provision:true, enabled:true}')"
do_request PUT /api/v1/settings/saml "$CFG" "$(auth_hdr)"
assert_status "200|201" "configure + enable SAML"

# GET login → 302 to the IdP SSO URL carrying a deflate+base64 SAMLRequest.
# (Do not follow the redirect — the IdP host is not real.)
read -r CODE LOC < <(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "$API_URL/api/v1/auth/saml/$SLUG/login")
if [ "$CODE" = "302" ]; then
  print_success "SAML login returns 302 (HTTP 302)"
else
  print_failure "SAML login returns 302" "got HTTP $CODE"
fi
case "$LOC" in
  https://idp.e2e.test/sso\?SAMLRequest=*)
    print_success "login redirects to IdP SSO URL with a SAMLRequest" ;;
  *)
    print_failure "login redirect target" "unexpected redirect: $LOC" ;;
esac

# A request-tracking cookie must be set so the ACS can bind InResponseTo.
COOKIE_HDR="$(curl -s -o /dev/null -D - "$API_URL/api/v1/auth/saml/$SLUG/login" | tr -d '\r' | grep -i '^set-cookie:.*saml_authn_')"
if [ -n "$COOKIE_HDR" ]; then
  print_success "login sets the saml_authn request-tracking cookie"
else
  print_failure "login request cookie" "no saml_authn_* Set-Cookie header"
fi

# Disabled config → login must refuse (error redirect, not a live AuthnRequest).
CFG_OFF="$(jq -n --arg c "$CERT" '{idp_entity_id:"https://idp.e2e.test/entity", idp_sso_url:"https://idp.e2e.test/sso", idp_certificate:$c, allowed_domains:[], default_role:"member", auto_provision:true, enabled:false}')"
do_request PUT /api/v1/settings/saml "$CFG_OFF" "$(auth_hdr)"
assert_status "200|201" "disable SAML"
read -r CODE2 LOC2 < <(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "$API_URL/api/v1/auth/saml/$SLUG/login")
case "$LOC2" in
  *"/login?error=saml") print_success "disabled SAML login → error redirect" ;;
  *) print_failure "disabled SAML login" "expected error redirect, got $CODE2 $LOC2" ;;
esac

e2e_finish
