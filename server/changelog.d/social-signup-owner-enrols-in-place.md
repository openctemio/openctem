### Changed: a social sign-up makes its personal organization under any two-factor floor

- A new account that signed up through a social provider now gets its personal organization at that sign-in even when the platform two-factor floor covers owners. The organization asks for a second factor as before (`MFA_ENROLLMENT_REQUIRED`, the session stays); the person enrols one in place within 15 minutes of the sign-in and then opens the organization. Before, the organization was held back (mark pending) until the person had a password and a factor.
- Docs: server/docs/architecture/user-onboarding.md
