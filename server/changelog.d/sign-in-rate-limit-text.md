### Fixed: the sign-in form says "Too many attempts" on a rate-limited sign-in

- A sign-in refused by the request rate limit (429, `RATE_LIMIT_EXCEEDED`) showed only "Sign-in failed", which reads like a wrong password. The form now asks the person to wait a minute and try again (en and vi).
- The e2e sign-in helper recognises that text again, so a worker that hits the per-address sign-in limit waits for the window instead of failing after 30 seconds; any other refusal fails at once with the form's message.
