### Security: a scan name cannot add code to a generated CI pipeline file

- The CI snippets (`GET /api/v1/scans/{id}/ci-snippet`: GitHub Actions, GitLab CI, Jenkins) wrote the scan name into their first comment line as it was. Any member who can edit scans could put a newline in a name and add YAML keys or Groovy code to a file an administrator commits, a file whose environment holds the OpenCTEM API key. The name is now folded to one line, cleaned of control characters and capped at 200 characters.
