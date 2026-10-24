### Security: creating a support grant, API key or stored credential fails closed when it cannot be audited
- A support access grant whose audit write fails is revoked at once; an API key is revoked (deleted if that fails) before its plaintext is returned; a stored credential is deleted. Each returns 503 instead of succeeding without an audit row.
- Failure logs of the support access audit writes are sanitized.
- The audit discard guard also flags bare, `go` and `defer` calls of audit writes (including `tenantEvent` and `adminEvent`); the module preset audit no longer drops its error.
