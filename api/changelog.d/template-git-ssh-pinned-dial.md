### Security: template-source clones over ssh connect only to the address that was checked

- A scanner-template source cloned over ssh was checked against the SSRF guard before the clone, but go-git then resolved the host again and dialled it itself. A DNS answer that changed in between (rebinding) could point the connection at an internal address.
- ssh clones and pulls now connect through the same guarded dialer as every other outbound request: it resolves the host once, refuses blocked answers, and connects only to the vetted address. https clones were already pinned this way.
