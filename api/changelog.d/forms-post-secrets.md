### Security: sign-in and other secret forms never submit as GET

- The sign-in, registration, password reset/setup, two-factor, request-access, admin password and identity-provider, TOTP step-up, scope self-approval, sensor pairing and storage settings forms declare `method="post"`. Before, a form submitted before its JavaScript loaded went out as GET, putting the password or code in the URL and in proxy and access logs. A test fails any form with a password or one-time-code field that does not post.
