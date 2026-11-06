### Added: an account space for a person with no organization

- Signing in with no organization opens `/welcome` instead of a dead end: the invitations sent to the verified address (accept or decline), links to profile, security, sessions, sign-in methods and preferences, and sign out. "Create an organization" appears only when the sign-up policy allows it for the person; on a self-hosted installation (the default) the page says to ask an administrator. The account pages render without the organization sidebar, and a page that needs an organization sends the person back to `/welcome`.
- The "Your organization isn't set up yet" page, shown for a refused sign-up, now lists next steps and names no organization.
