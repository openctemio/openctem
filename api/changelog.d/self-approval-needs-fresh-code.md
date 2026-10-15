### Security: an owner approving their own exposure disposition or suppression rule needs a fresh authenticator code

- A lone owner's accept or false-positive request on a high or critical exposure or leaked credential is no longer applied automatically: it stays pending, and the owner approves it in a separate call (`self_approve: true`, a reason and `totp_code`) only when no other approver exists.
- Approving one's own suppression rule (a lone owner) now needs `self_approval_reason` and a fresh `totp_code`; a plain approve by the requester is refused.
- Refused own approvals are audited High (`exposure.disposition_self_approval_refused`, `suppression_rule.self_approval_refused`); successful ones stay Critical.
- **Upgrade note:** an owner without an authenticator app can no longer approve their own requests; set one up, or have a second approver decide.
