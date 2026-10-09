### Fixed: the pentest retest dialog and activity feed use the current finding statuses

- A passed retest is described as Resolved (retest verified) for leads and
  reviewers and Fix applied for testers, a failed one as In progress, with the
  labels taken from the shared status registry; the activity entry reads
  "Retest verified" instead of the retired "Verified" status.
