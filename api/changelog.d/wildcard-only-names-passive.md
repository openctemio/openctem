### Security: names that resolve only through a wildcard DNS record are never scanned actively or confirmed automatically

- A finished dnsx resolution with the wildcard-DNS filter on marks the names it was given and did not report: they resolve only through a wildcard record of their zone (or not at all). A later filtered resolution that reports a name clears its mark.
- The active-probe gate refuses a marked name, and a service or URL on it, with the new refusal code `wildcard_only` until a person confirms the asset or the mark clears. A scope entry covering the name no longer lets probes reach it.
- The scope join (auto-confirmation of discovered names under a permanent scope entry) never confirms a marked name.
- Migration `asset_wildcard_dns`: a new, empty table; nothing existing changes until the next filtered resolution finishes.
