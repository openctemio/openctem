### Security: loosening the closing mode waits 24 hours

- A change that lets the platform close more findings alone (off to review or auto, review to auto, critical findings without review) now takes effect 24 hours later; until then the stricter policy applies. The waiting change shows in `pending_mode`, `pending_critical_auto_close` and `pending_at`, owners and administrators are told, and `DELETE /api/v1/organization/settings/closure/pending` cancels it. Tightening stays immediate.
- Settings > Finding lifecycle has a Closing findings section (en, vi), and the finding's verification plan now says why a covered scan will not close it: critical findings wait for review in auto mode, the organization reviews every close, or closing is off for the organization.
