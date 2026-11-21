# Runbook: moving provider shared addresses into their names' history

The `provider-addresses` command folds an organization's provider shared
addresses (addresses inside ranges a provider publishes for infrastructure
many organizations share) into the address history of the names that
resolve to them, moves services named by a host name to that name, and
archives the provider addresses that carry nothing else. How it decides is in
[architecture/provider-address-move.md](../architecture/provider-address-move.md).

It never runs by itself. It is a dry run unless `-apply` is given, and it
changes one organization at a time.

## F0. Order

1. Deploy the release (code first). The command ships with it, off.
2. Run the dry run for every organization and read the report.
3. Apply on the staging installation, one organization at a time, and check
   the results (F3).
4. On production: apply only after the owner of the installation agrees (a
   data change on production).
5. About 24 hours later run the apply again: during a rolling deploy, replicas
   still on the old code can create a few more provider addresses. The second
   pass picks them up and changes nothing else.

## F1. Where to run it

Inside the API container (it reads `DB_*` like the server) or anywhere with
`DATABASE_URL` set:

```sh
provider-addresses                                  # dry run, every organization
provider-addresses -tenant <organization id>        # dry run, one organization
provider-addresses -tenant <id> -apply -progress    # apply, one line per batch
provider-addresses -tenant <id> -restore            # put back what applies changed
provider-addresses -json                            # the reports as JSON
```

Other flags: `-batch` (address assets read per batch, default 500),
`-batch-shared` (provider addresses changed per batch at most, default 150;
a batch ends early when it holds that many),
`-max-batches` (stop early; a later run continues), `-timeout` (default 2h).
Exit status 0 is success, 1 is a failed run, 2 is a usage or connection
error.

## F2. Reading the dry-run report

The dry run reads everything, changes nothing, and stores one `dry_run` row in
`provider_address_moves` with the counts. The report prints counts only,
never names or addresses:

```text
provider-addresses dry run (nothing changed)
  organization   <id>
  dataset        <dataset version> (job version 1)
  run            <run id>
  batches        <n>, <n> address assets read, <time>, finished

Addresses inside published shared ranges: <n>
  provider   group               addresses
  <name>     plain               <n>
  <name>     plain_after_relink  <n>
  <name>     address_services    <n>
  <name>     entry               <n>
  ...

Name-to-address links folded into the names' address history: <n> (<n> not yet in that history)
Services moved from an address to their name: <n>; certificates moved: <n>
  findings on those services: critical <n>, high <n>, medium <n>, low <n>, none <n>
Services named by the address (stay on the kept address): <n>, findings on them: <n>
Addresses archived: <n>; kept: <n>; attribution set to dependency: <n>
Skipped (target of a queued or running scan, next pass): <n>
Restored because their range left the dataset: <n>
Edges deleted (journaled): <n>; edges added: <n>; journal items: <n>
Scope entries for the scope card: <n> exact, <n> ranges inside a shared range (exact import <n>, ...)
Inventory total: <n> before, <n> after
Finding status changes: 0
```

Check before applying:

- "Finding status changes" is 0. The apply checks it again per batch and
  stops if it is not.
- "kept" covers what you expect: addresses with their own services, scope
  entries, a person's decision or any other reference stay.
- Scope entries for the scope card are not changed by this command; the
  organization decides them on the scope card.

## F3. Applying

```sh
provider-addresses -tenant <id> -apply -progress
```

Each batch is one short transaction: it waits at most 2 seconds for a lock
and 30 seconds for a statement, and is retried when it hits either. A second
runner on the same organization reports "another run holds this
organization". If the command stops (a timeout, a deploy, a killed process),
run the same command again: it continues after the last committed batch. A
second apply after a finished one changes nothing.

At the end the organization gets one audit entry
(`asset.provider_addresses_moved` with the counts), one dashboard refresh
request and, once per organization, a notice in its notification feed
("Shared provider addresses moved to your names", with the counts).

Expected result: the apply's counts equal the dry run's. Check in the console
that the names still show their services and findings, and that the asset
total dropped by the archived count while finding totals did not change.

## F4. Restore and rollback

- **(a) Per organization:** `provider-addresses -tenant <id> -restore`.
  Every address still as the move left it gets its status, attribution and
  edges back, and the edges and history rows the move added are removed. An
  address a person or a scan changed since is left as it is and counted as
  "changed". One audit entry `asset.provider_addresses_restored`.
- **(b) Code rollback** to the previous release: archived assets, history rows
  and missing edges are states the previous release already handles. The
  previous ingest may recreate some edges and provider addresses, which is
  harmless; the next apply after re-deploying handles them.
- **(c)** The journal's down migration is only for a full revert after (a).
  Never drop the journal while items with outcome `applied` exist: it is the
  only record of what an apply changed.

## F5. Performance

Measured on a synthetic set before merge (see the pull request): per-batch
time, and EXPLAIN of the batch read, the fold upsert, the relink insert, the
edge delete and the archive update. Each batch commits in well under a
second; lock waits are bounded at 2 seconds.

## F6. Notice text

English: "We moved N shared provider addresses (providers) into the address
history of M of your names. They were never yours to scan; the names stay
monitored. Nothing was deleted: open a name and choose Addresses to see
them." When the organization has scope entries inside shared ranges: "K scope
entries need your decision." The Vietnamese text is stored next to it on the
run row (`provider_address_moves.notice`) for the console.

## Troubleshooting

- "another run holds this organization": a second runner or a restore is in
  progress; wait for it and run again.
- "a finding status changed inside the batch": the batch was rolled back and
  the run marked failed. Nothing was changed by that batch. Find what changed
  the finding (a trigger or a concurrent job) before running again.
