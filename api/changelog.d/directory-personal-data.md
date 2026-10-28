### Security: the console directory shows less personal data below the roles that need it

- Accounts linked to a platform administrator are no longer listed (rows, tab counts) or readable (404) in Users below super admin; before, an ops admin could list them with their sign-in sessions.
- Reads of the Users directory are limited to 120 per minute per administrator.
- The Organizations list no longer carries owners' email addresses: ops admin and above get the owners' domains, read-only gets the owner count. The organization's own page still shows the owners' addresses to ops admin and above, and each view is now written to the admin audit log (`organization.view`).
- A read-only administrator no longer sees the free-text suspension reason of an organization, nor the requesters' addresses and notes in the access-request queue (addresses are masked, notes are not sent).
