### Fixed: a re-verification step that cannot load now says so (redesign branch)

- When an action asks to confirm your identity again and the browser cannot download that step (offline, or a
  new version was deployed meanwhile), an error message now says the verification step could not be opened and
  to check the connection and try again. The action is still refused, as before. Trying the action again
  downloads the step again.
- Docs: none (error message for a network failure; no behaviour to document)
