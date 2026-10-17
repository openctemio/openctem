### Security: the CI gate fails when the job reports a capability that did not reach the platform

- The CI runner (openctemio/ci v0.4) sends each capability's state with the verdict request. The gate now reads
  it: a capability that failed, uploaded only partial results, was not uploaded or is missing fails the run
  with `capability_failed` ("Scan did not reach the platform"), naming the capability, its tool and the reason,
  even when the job's `scan_failures` count is zero. Unknown states count as not clean. Older runners that send
  no states are judged as before.
