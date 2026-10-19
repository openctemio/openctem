### Changed: a name that does not resolve is refused as `unresolved`, not as a private target outside every scan zone

- Scan target checks (`POST /api/v1/scope/check`, dispatch refusals, skipped targets) answer the new refusal code `unresolved` for a hostname the platform could not resolve in DNS. It used to be reported as `zone_none` ("No scan zone covers this private target"), which was wrong for a public, in-scope name.
- The New scan and Quick scan summary reads "N can be scanned" and counts unresolvable names on their own; Review groups them with the fix (repair the DNS record or scan the address).
- **Upgrade note:** clients that switch on refusal codes should treat the new `unresolved` code as a refusal with no fix action.
