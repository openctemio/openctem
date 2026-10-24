### Security: an organization's SMTP relay is bounded in time and limited to mail ports

- The email notification channel bounds a whole SMTP session (connect, TLS, greeting, authentication, delivery) to 2 minutes, or the caller's deadline when earlier. A relay that accepts the connection and never answers no longer holds a delivery worker or a connection test.
- An organization's SMTP relay must use port 25, 465, 587 or 2525. Create and update refuse other ports; a relay stored on another port is not dialed (notifications fail with a clear error, and transactional mail uses the platform relay instead).
- The platform relay set in the console is not restricted.

### Behaviour change: email notification channels on a non-mail port stop delivering

- **Upgrade note:** an organization whose email channel uses a port other than 25, 465, 587 or 2525 must change it to one of these.
