### Security: the console's CSRF token is bound to its session

- The platform console's CSRF token is now HMAC-SHA256 of the console session under a server key derived from `AUTH_JWT_SECRET` (shared by the replicas), and the API verifies that binding on every console write instead of comparing the header with the `admin_csrf` cookie. A cookie planted by a script on another site of the same host (cookies ignore ports) can no longer satisfy the check.
- Every `/api/v1/admin` response, the sign-in and validate responses included, is `Cache-Control: no-store`.
- **Upgrade note:** a console tab open when this ships gets 401 on its next change; reloading the page (which fetches the bound token from validate) or signing in again fixes it.
