### Fixed: "outdated permissions" error after a role or team change

- A write right after a role or team change was refused with "Your session is using outdated permissions. Refresh your token and retry." The web client only reloaded the permission list, never the session token that carries the permission version, so every write kept failing until the next sign-in or token expiry. It now refreshes the session and retries the write once; a second refusal or a failed refresh shows the error as before.
