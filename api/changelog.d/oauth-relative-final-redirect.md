### Fixed: social login refused every sign-in with "Invalid redirect URI"

- Sign in with Google, GitHub or Microsoft failed with "Could not sign in with Google. Try again." because the API checked the page to return to after sign-in (`final_redirect`, `/` by default) as if it were a full URL and refused the plain path. A path on the same site is now accepted; protocol-relative (`//host`), backslash and control-character forms are still refused, and absolute URLs must still match the sign-in callback's origin.
