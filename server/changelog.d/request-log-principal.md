### Security: the request log names who a request authenticated as

- Each request log line now carries `user_id` and `tenant_id` (or `admin_id` on the platform admin plane) once the request authenticated, so refused (401/403) and failed requests can be attributed to an account and organization. Identifiers only, never an e-mail.
