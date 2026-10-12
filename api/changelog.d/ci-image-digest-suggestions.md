### Added: CI container scans suggest links from the repository to the workloads running the image

- When a CI run's container report carries the image's content digest
  (`metadata.properties.image_digest`, sent by openctem-ci), the platform
  suggests relationships from the run's repository to the organization's
  assets whose properties carry the same digest: `contains` for a container
  image asset, `deployed_to` for a Kubernetes workload or cluster, or a host.
  They appear in the relationship review (confidence 0.8); nothing is linked
  without approval, since the digest is the job's own report.
