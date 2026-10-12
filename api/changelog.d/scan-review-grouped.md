### Changed: New Scan review groups refused targets by reason, with one action per group

- The Review step no longer lists every refused target with its own buttons.
  Targets are grouped by reason, with counts (for example "212 need a
  verified domain for platform sensors" or "69 resolve to private addresses
  outside every scan zone"). Each group is collapsible, shows a few examples
  with "Show all", and has one action for the whole group: "Run on your own
  sensor", "Verify <domain>", approve or activate the covering scope entry,
  "Set up a scan zone", or "Remove these targets". There is also a Remove all.
- "Scan the N allowed targets, skip the rest" saves the scan with only the
  allowed targets. The server records the skipped ones with their reasons.
- "Runs on" explains the choice, for example "Auto -> runs on your sensor
  sensor-docker-01, because platform sensors need a verified domain".
- The scope check runs again whenever the Review step opens, and on
  "Re-check".
- A private target reads "Resolves to 10.x.x.x, an internal address:
  scanning it would hit your own network".
- Fixed: the New Scan dialog body scrolled sideways and clipped its content
  when a long list of names was shown (a fieldset was as wide as its
  longest line).
