### Added: approvers are told about false-positive requests made by VEX statements

- When VEX `not_affected` statements in scan reports request false positives
  (`INGEST_VEX=enforce`), every approver gets one batched in-app notice and
  one email per run of the new `vex-request-notice` job (every minute),
  counting only the findings in their own data scope and naming at most five
  of their titles. An approver who can see none of them is not told; without
  a data-scope check nobody is told (fail closed). A platform actor made the
  requests, so nobody is excluded as requester.
- The requests table is the outbox: ingest only writes the request, the job
  claims unannounced rows (`approvers_notified_at`, `FOR UPDATE SKIP LOCKED`)
  so a large report never slows the ingest and nothing is announced twice.
  Migration `002763` (`finding_approval_actor_notified`): a nullable column and
  a partial index.
