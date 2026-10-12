### Removed: web compatibility shims from before the sensor rename

- The web UI no longer reads `NEXT_PUBLIC_SSE_BASE_URL`. Set
  `NEXT_PUBLIC_WS_BASE_URL` instead (no shipped deploy file sets the old name).
- The one-time browser-storage migration from the agent vocabulary
  (`openctem_perms` `agents:*` values and `agent`-named app keys) is gone;
  browsers that last loaded the UI before the rename show the defaults for
  those keys once.
