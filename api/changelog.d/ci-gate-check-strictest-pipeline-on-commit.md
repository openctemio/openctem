### Security: a second pipeline on a commit cannot turn a failing "OpenCTEM gate" check green

- The GitHub check and the GitLab commit status of a commit now take the
  strictest of the latest verdicts of every pipeline on that commit. Before,
  each run posted its own verdict under the same name, and the code host
  keeps the latest one: a second workflow added by the pull request, or any
  later passing run of another pipeline, replaced a failing check. A re-run
  of the same pipeline still replaces its own earlier verdict.
- The GitHub App guide and the console tell administrators to set the
  required check's expected source to the OpenCTEM app, so a workflow's own
  token cannot post a check with the same name.
