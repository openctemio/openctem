### Added: request access when sign-up is closed

- With the sign-up policy at `admin_only` and request access on, the "not set
  up" page offers a request form (`/request-access`, en/vi;
  `POST /api/v1/auth/access-requests`). Every accepted submission gets the
  same answer; per-address (3/hour, IP kept only as a hash) and per-domain
  (5/day) limits and disposable addresses drop requests silently. With SMTP
  the requester confirms by an emailed link first.
- Console > Organizations > Access requests: any admin sees the queue;
  ops admins approve (the organization is created with the requester as its
  owner) or reject (a neutral email). Both are admin-audited.
- Unconfirmed requests are deleted after 24 hours and decided ones after 90
  days (migration 001380, new table `access_requests`).
- **Upgrade note:** `CAPTCHA_TURNSTILE_SECRET` / `CAPTCHA_TURNSTILE_SITE_KEY`
  prepare a CAPTCHA on the form; the web widget is not wired yet, so leave the
  secret unset for now.
