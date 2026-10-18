### Added: platform console Configuration page and version check switch

- Settings > Configuration lists every operator setting with where it is
  managed (this console, applied at once, or the server, restart needed),
  where its value comes from (console, server, default), who last changed a
  console setting, and the page that changes it. Secrets show only whether
  they are set. `GET /api/v1/admin/configuration`, any admin role.
- System > Software updates can turn the daily version check on and off
  without a restart (super admin, step-up, audited `version_check.switched`).
  `VERSION_CHECK_ENABLED=false` stays a ceiling: the console cannot turn the
  check on.
