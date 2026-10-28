### Security: elevating a console session needs a fresh code

- `POST /admin/auth/elevate` used the five-minute step-up window, so any step-up in the last five minutes (removing a key, ending a session, starting a support session) let the same session elevate to super administrator for up to an hour without a code. Elevation now takes a fresh authenticator code or a security-key confirmation given within the last minute. That proof opens the step-up window, so the first protected action after elevating needs no second code.
