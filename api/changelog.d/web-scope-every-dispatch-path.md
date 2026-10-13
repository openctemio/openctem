### Security: path exclusions bind every web job, not only workflow steps

- A quick scan, a single-scanner scan (scheduled or retried included), a
  zone batch and a command created through the API ran crawl, template and
  web application tools without the job's web scope, so a host's excluded
  paths (for example `/admin`) were requested. Every command now passes one
  guard when it is stored: a job whose tool requests web paths gets the
  deny paths of its own organization's path exclusions, or is refused when
  they cannot be read.
- A nuclei validation or retest on a host with a path exclusion is refused
  (`WEB_SCOPE_UNSUPPORTED`): the sensor cannot keep such a job to a web
  scope yet.
