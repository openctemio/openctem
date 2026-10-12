### Security: suspending or removing a member in one organization no longer signs them out of their other organizations

- Disable, offboard and SCIM deprovisioning used to revoke every session of the person. The person's other organizations were affected too: an administrator of one organization could sign a member of another out at will.
- The organization's own access is still cut at once:
  - membership checks on every request and at token exchange;
  - caches dropped and sockets closed;
  - the sessions its own identity provider signed in are revoked.
- Sessions that serve the person's other organizations stay.
- A person with no other organization left still loses every session.
- Erasing personal data still ends every session, and so do account-wide actions: a password reset, or a platform administrator disabling the account.
