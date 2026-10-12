### Security: when your company removes you, your access to its partner organizations ends too

- Disabling or offboarding a member (including SCIM) suspends their external memberships in every other organization that has them as members of this organization (RFC-058).
- Host administrators are notified, and both organizations' logs record it.
- When this organization holds the person's email domain, every session of the person also ends.
- Re-enabling the member restores those memberships.
- An organization that stops holding an SSO domain (lapsed DNS proof, or removed) suspends the external memberships it managed through that domain. Proving it again restores them.
- A host's own suspension is never undone.
