### Fixed: the layout matrix no longer sends a made-up client address

- The entry-page states of the layout matrix (forgot password, reset password,
  verify e-mail) sent their own X-Forwarded-For so the per-address limit on
  password and link requests would not refuse one state after another. They
  send none now: the scratch stack the matrix runs on gives each request its
  address. The verification link request is sent by the page itself, as the
  sign-in page does, and its answer is written to the run log.
- Docs: none (test tooling only; no guide describes the matrix states)
