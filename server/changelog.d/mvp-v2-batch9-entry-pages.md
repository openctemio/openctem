### Changed: the layout matrix checks the sign-in and link pages in their real states

- The viewport matrix opens /reset-password with a token (the new-password form) and after a refused token (expired link), /login after wrong credentials, /forgot-password after the request, /register from an invitation link, and /oauth/device with an unknown code, beside the bare pages.
- /oauth/device runs signed in, as it needs a session; before, the matrix opened it signed out and checked the sign-in page instead.
- Docs: none (test harness only; no page, request or wording changes)
