### Added: security keys in the platform console screens

- Console sign-in offers "Use security key or passkey" first when the administrator has one, with the authenticator app (when still allowed) and a one-time recovery code as fallbacks.
- The step-up dialog confirms protected actions with a key and retries the action inside the five-minute window; forms that ask for an authenticator code accept an empty code from an administrator with a key.
- New page Security > My security keys: add, rename and remove keys, and generate recovery codes (shown once, copy or download, acknowledged before the dialog closes).
- System > Admin sign-in gets the "Require security keys" switch; under the policy an administrator who still has to enroll sees only the security-keys page until they comply.
