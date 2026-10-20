### Security: a leaked secret is no longer resolved because a scan stopped reporting it

- A full default-branch scan, and a covered scan of other assets, used to close a secret finding as `fixed` / `covered_scan` when the secret was no longer reported. Removing a secret from the branch does not revoke it, so neither path closes secrets now (finding type or source `secret`); the resolve statements refuse them as well.
- Instead the finding stays open, is marked stale (not observed) and gets a timeline entry. A new sighting makes it present again; a person with `findings:verify` closes it once the credential is rotated.
- A retest is no longer offered for a secret finding, so a retest with `retest.auto_resolve` cannot close one either.
- **Behaviour change:** secret findings that used to disappear after a clean default-branch scan stay open until a person resolves them. Fix-rate figures no longer count them as fixed by a scan.
