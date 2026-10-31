### Fixed: signing in after a deploy no longer fails in a tab that was already open
- The web build sets a Next.js deployment id (from the build commit), so an old tab reloads on its next navigation instead of calling server actions that no longer exist.
- A client guard watches for the "server action not found" response, shows "OpenCTEM was updated" and reloads once (never in a loop). It covers sign-in, SSO and social start, account linking and every other server action.
