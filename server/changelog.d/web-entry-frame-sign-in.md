### Changed: sign-in page in the new entry frame

- Pages without the app shell (sign-in first; sign-up, password links, verification, two-factor, organization choice, onboarding, application consent follow) share one frame: the brand, one card of a fixed width, one primary action, the legal links and a language menu in the footer. On a phone the card is the screen.
- Sign-in: the title is the page's heading, provider buttons show their name, "Forgot password?" sits beside the password label, notices from a callback read as a banner in the card, and the two-factor step carries its own title.
- Sign-in failures (wrong password, locked or suspended account, security check, a provider that could not start, an expired two-factor challenge) and the reason a session ended now stay in the card above the form as an alert the form refers to, instead of a toast that fades. The texts are the same.
- Requests, redirects, cookies, error texts, what a message reveals about an account, code auto-submit and autofill attributes are unchanged.
- Docs: web/docs/ui-style-contract.md ("Entry pages")
