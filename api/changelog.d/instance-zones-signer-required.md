### Security: instance scan zones need the job signer and the setting at signing time

- A zone is never created, changed or deleted while no job signer is wired.
- A shared job's signed statement names a zone only while "shared sensors may
  scan internal zones" is on, checked again at signing.
- The signer's zone ledger records the administrator id, not the email.
