### Removed: automatic linking of social sign-in to an existing account

- The "Link Google and Microsoft sign-in to existing accounts" setting (`social_auto_link`) is gone from Console > Settings > Sign-up, from the sign-up policy API (`GET`/`PUT /api/v1/admin/settings/signup`) and from the audit of policy changes. No setting can make a sign-in link itself: a sign-in whose address belongs to an existing account is always refused with `409 OAUTH_ACCOUNT_EXISTS` and linking needs the person's typed proof.
- Migration `signup_policy_drop_social_auto_link` removes any stored `social_auto_link` value from the sign-up policy and keeps the rest.
- The security notice e-mail for a new link no longer has an "automatic" wording; `auth.identity_linked` rows written earlier with `how=automatic` stay readable.
