### Security: password reset and setup links carry their token in the URL fragment

- The forgot-password link and the set-password link an administrator sends
  (or `bootstrap-admin` prints) are now `/reset-password#token=…` and
  `/set-password#token=…`. A token in the query string reached web-server and
  proxy access logs and the Referer of requests the page made; the fragment
  is never sent to a server. Verification and invitation links already did
  this.
- The pages read the fragment, still accept a query token from links sent
  before this change, and remove the token from the address bar at once.
