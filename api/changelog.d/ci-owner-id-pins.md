### Security: CI trust pins each organization's immutable id

- A GitHub or GitLab trust configuration matches organizations by name. The
  first admitted exchange now pins the name to its immutable id (GitHub
  `repository_owner_id`, GitLab `namespace_id`; table `ci_trust_owner_pins`,
  migration `ci_trust_owner_pins`, audited). A later token with the same name
  and another id (an organization renamed or deleted and its name registered
  by someone else) is refused and audited (`owner_id_mismatch`). Changing the
  configuration's issuer, owners or repositories drops its pins, which are
  taken again at the next run; `GET /api/v1/ci/trust-configs/{id}` lists them
  (`owner_pins`).
