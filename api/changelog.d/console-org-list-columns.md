### Changed: platform console organization list shows status and last member sign-in

- The organization list has a Status column (Active, Suspended, Deletion scheduled, as the shared state pill) with a status filter, and a "Last member sign-in" column.
- `GET /api/v1/admin/tenants` returns `last_member_sign_in_at`: the latest sign-in of any active member. Sign-in times are kept per account, so a member's sign-in for another organization counts.
