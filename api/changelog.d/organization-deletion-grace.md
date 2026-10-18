### Behaviour change: deleting an organization waits 14 days, and owners can cancel

- An owner's `DELETE /api/v1/tenants/{tenant}` now answers 202 with
  `deletion_due_at` instead of deleting at once. The organization is closed to
  every credential from that moment (the same gate as a suspension) and the
  `organization-delete` worker deletes it when the 14 days end.
- Any active owner can cancel until then from the sign-in page
  (`POST /api/v1/auth/organization-deletion/cancel`, refresh-token
  authenticated); everything works again as before.
- Console > Organizations: "Delete now" (super_admin, fresh authenticator code,
  reason, critical admin audit) deletes an organization at once, whatever its
  status.
- Migration `organization_deletion_grace` adds the `pending_deletion` status
  and the `deletion_requested_at`, `deletion_requested_by` and
  `deletion_due_at` columns.
