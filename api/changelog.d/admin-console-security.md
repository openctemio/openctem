### Added: console sessions and a better admin activity log

- Security > Sessions (super admin) lists every open console session: who, role, break-glass, how they signed in, from where, last seen. Ending one (`DELETE /api/v1/admin/sessions/{id}`) needs a reason and a fresh authenticator code, signs that administrator out at once, and is audited at high severity.
- Security > Admin activity filters by date range, opens each entry in a detail sheet (the request as stored, secrets redacted) and exports the filtered page as CSV.
