### Fixed: social login always ended on "Sign-in could not be completed"

- After choosing an account at Google, GitHub or Microsoft, the web app's callback ran as a page, and Next.js refuses cookie writes during a page render, so storing the session failed every time. The callback is now a route handler; the page to return to after sign-in is also honoured again (it was cleared before being read).
