### Fixed: sign-in and entry pages share one way back and one broken-link state

- Every entry page (forgot, reset and set password, register, request access, not set up, invitations) has the same "Back to sign in" button: outline, with a back arrow, last in the card. Signed in, the invitation and application-consent pages lead to the dashboard the same way.
- A link that does not work (reset, setup, e-mail verification, access-request confirmation, invitation, application consent) is one card titled by the problem ("This reset link does not work"), one plain sentence, at most one way on, then the way back: no red banner under the page's normal title, no two stacked notices.
- Reset password on a server that cannot send e-mail no longer offers "Request a new reset link" (it led to a page that said reset by e-mail is off); it says to ask the administrator.
- Sign in and register: the terms and privacy links show once, in the consent line; the frame footer hides its copy of them there.
- Legal pages: no contact footer repeating the contacts the document already gives.
- Docs: web/docs/ui-style-contract.md, "Entry pages" (EntryBackLink, EntryLinkProblem, legal links once per screen)
