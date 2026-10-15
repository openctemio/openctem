### Fixed: GitLab merged results pipelines get the gate status and the merge request note

- A merged results pipeline runs on the commit GitLab makes by merging the head into the target, never on the
  merge request's head, so its verdict was always skipped as "the merge request has newer commits": no status
  and no note. It is now posted when the run's pipeline is the merge request's head pipeline and its commit is
  the run's verified commit; the status is attached to that pipeline (`pipeline_id`), which the merge request
  shows. Merge train pipelines are still not decorated.
