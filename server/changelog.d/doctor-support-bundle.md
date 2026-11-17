### Added: `server doctor` and `server support-bundle`

- `server doctor` checks an installation and prints a table of checks (pass, warn, fail), each with one
  sentence and the fix: configuration, public URL, key settings (presence and shape only), database
  reachability, the privileges of the database role, migrations, clock skew against the database server,
  Redis, certificate expiry, free disk space, backup age, queue backlog and stuck jobs, sensor heartbeats
  and versions (counts), and the known link breaks of the audit chain (reported, not judged). Exit code 0
  only when nothing fails; `--json` for scripts.
- `server support-bundle` writes one archive that is safe to send to someone with no access to the
  installation: the doctor's result, build information, every setting as set / not set (values only for
  settings that cannot hold a secret, a name or an address), database statistics from the catalog and
  statistics views, queue statistics, and the logs of the period with e-mail addresses, IP addresses, host
  names, tokens, cookies, authorization headers, bodies and evidence masked. It holds no database row, no
  finding, no asset, user or organization name and no key. Options: `--since`, `--max-size`, `--output`,
  `--logs`.
- Both commands only read: every SQL statement runs in a read-only transaction with a statement timeout.
  There is no HTTP route; whoever can start a process in the server's container can run them.
- Docker Compose: `./support.sh doctor` and `./support.sh bundle` in `server/deploy` (also in the Compose
  bundle). Kubernetes and the Ansible kit: one `exec` line each, in the guide.
- Docs: server/docs/operations/diagnose-and-get-support.md
