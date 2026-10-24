### Security: step-up on sensor and service-account deletes, audit-log export, scan approval and test-credential reveal

- Deleting a sensor, deleting a service account, exporting the audit log, approving a held scan, and revealing or deleting a pentest campaign test credential now need a recent sign-in (`403 STEP_UP_REQUIRED`, then the verification dialog and one retry).
- Revoking a sensor, an API key or a SCIM token stays one click: it only narrows access and is the incident path.
- The web audit-log export asks for verification when the API requires it and retries once.
- Behaviour change: these routes now refuse API-key callers (`403 STEP_UP_UNAVAILABLE`), as every step-up route does; scripts that deleted sensors or service accounts, approved scans or exported the audit log with an API key must use a signed-in session.
