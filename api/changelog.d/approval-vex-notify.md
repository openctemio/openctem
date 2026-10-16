### Added: approvers are told about false-positive requests made by VEX statements

- When VEX `not_affected` statements in a scan report request false positives
  (`INGEST_VEX=enforce`), every approver gets one in-app notice and one email
  per report, counting only the findings in their own data scope and naming
  at most five of their titles. An approver who can see none of them is not
  told; nobody is excluded as requester because a platform actor made the
  requests. The link opens the approvals inbox (sign-in required).
