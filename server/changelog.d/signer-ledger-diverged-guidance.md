### Changed: the scope ledger divergence warning says how to resolve it

- The API's periodic ledger sync warning ("scope in effect that the job signer's ledger does not hold") now names both ways out: the ledger bootstrap (export, review, import with `-replace`) for scope that was in effect before the ledger existed, and taking an entry out of effect and approving it again for anything else. Saving an entry unchanged never sent it to the ledger, so the old advice ("until the scope is approved again") did not clear the warning on an upgraded installation.
- The job signing guide explains when the warning appears on an upgraded installation, that an organization with nothing in the ledger is not synced (no warning), and that the bootstrap of a ledger which recorded changes in `audit` needs `-replace`.
- **Upgrade note:** an installation upgraded with scope already in effect that still runs `SIGNER_LEDGER=audit` should run the bootstrap before switching to `enforce`; otherwise jobs for that scope are refused.
- Docs: server/docs/architecture/job-signing.md#bootstrap-and-restore-the-ceremony
