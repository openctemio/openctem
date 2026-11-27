### Fixed: Accept on the invitation page works from the first click

- Right after the invitation appeared, a click on Accept (or Decline) could do nothing: the page held the invitation's token in a separate update that could arrive after the invitation was drawn, and the click in between was ignored without a word. The token and the invitation now arrive in one update, so the buttons work as soon as they show. This made the invitation e2e spec fail on slow CI runners.
- Docs: none (no change to the flow, wording or API)
