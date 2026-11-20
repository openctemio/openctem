### Fixed: password, verification and access-request pages show one clear next step

- Forgot password: the "Check your email" card and the "no e-mail on this server" card make Back to sign in the main action; the no-e-mail case keeps the page title and says it in a warning notice.
- Reset and set password: an invalid link's one way on is the main action; an expired set-password link says to ask the administrator instead of "request a new one".
- Verify email: sending a new link reports success and failure as notices in the card (also on the sign-in page and the welcome page), and a server without e-mail says so in a notice with Sign in as the main action.
- Request access: a refused request shows translated words for the API's answer instead of the server's English sentence; the "Thanks" card makes Back to sign in the main action; a confirmation link that failed offers "Send a new request".
- Docs: none (presentation of existing pages; no behaviour, request or wording of the API changes)
