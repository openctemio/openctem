### Security: scheduled scans never run as the system

- A cloned or imported scan now belongs to the person who cloned or imported
  it (`created_by`), whose act scope is checked on its direct targets. Before,
  the copy had no owner, so its scheduled runs acted as the unrestricted system
  and could scan what the person could not (research 21b H2/H3, RFC-050 W2).
  `POST /scans/{id}/clone` and `POST /scans/import` need an authenticated user.
- A scheduled run of a scan with **no owner is refused** (`SCAN_HAS_NO_OWNER`,
  audited), and a scheduled run whose owner is no longer an active member
  (disabled or offboarded) **pauses the scan** and is refused
  (`SCAN_OWNER_INACTIVE`, audited). Manual triggers by a person are unchanged.
- **Upgrade note:** scheduled scans created before this release by clone or
  import have no owner and stop running on schedule. Find them with
  `SELECT id, name FROM scans WHERE created_by IS NULL AND schedule_type <> 'manual' AND status = 'active'`
  and clone or re-save each as the member who should own it.
