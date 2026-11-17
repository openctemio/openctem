# Diagnose and get support

Two commands of the server binary tell you what is wrong with an installation
and let you ask for help without giving anyone access to your data:

- **`server doctor`** checks the installation and prints a table: every check
  passes, warns or fails, with one sentence and the fix.
- **`server support-bundle`** writes one archive with the doctor's result,
  versions, settings as *set / not set*, database and queue statistics and
  masked logs. It holds no database row, no finding, no asset, user or
  organization name, no uploaded file and no key. You read it, then you send
  it.

Both only read. Every SQL statement runs in a read-only transaction with a
statement timeout; no file, key or setting is changed.

## Run it

| Installation | Check | Support bundle |
|---|---|---|
| Docker Compose (the bundle or a checkout, in `server/deploy`) | `./support.sh doctor` | `./support.sh bundle` |
| Ansible kit (on the host) | `docker exec <api container> /app/server doctor` (below) | see below |
| Kubernetes | `kubectl -n <namespace> exec deploy/<api deployment> -- /app/server doctor` | see below |
| Binary install | `openctem-server doctor` (as the service user, with the service's environment file loaded) | `openctem-server support-bundle --logs <log file>` |

### Docker Compose

```bash
cd server/deploy            # or the directory of the Compose bundle
./support.sh doctor         # the table; exit code 0 only when nothing fails
./support.sh doctor --json  # the same as JSON
./support.sh bundle         # writes openctem-support-<UTC time>.tar.gz here, mode 0600
./support.sh bundle --since 72h --max-size 50M --output /tmp/case-1234.tar.gz
./support.sh bundle --no-logs
```

`support.sh` runs the command in the `api` container. When that container is
not running (it keeps restarting), it starts a one-off container of the same
image with the same settings, so the doctor still tells you why the server
does not start. The bundle takes the logs of `api`, `web`, `console`,
`gateway` and `migrate` for the period; the database's own log is never read,
because it can print statements with their values.

### Ansible kit

The kit runs the same Compose stack. On the host:

```bash
api="$(docker ps -q -f label=com.docker.compose.service=api | head -1)"
docker exec "$api" /app/server doctor
docker logs --since 24h "$api" 2>&1 |
  docker exec -i "$api" /app/server support-bundle --logs - --output - > openctem-support.tar.gz
chmod 600 openctem-support.tar.gz
```

### Kubernetes

```bash
kubectl -n <namespace> exec deploy/<api deployment> -- /app/server doctor
kubectl -n <namespace> logs deploy/<api deployment> --since=24h |
  kubectl -n <namespace> exec -i deploy/<api deployment> -- \
    /app/server support-bundle --logs - --output - > openctem-support.tar.gz
chmod 600 openctem-support.tar.gz
```

The container's file system is read-only, so the archive is written to
standard output (`--output -`) and saved where you run `kubectl`. The summary
of what was included is printed on standard error and does not end up in the
archive.

### Who can run it

Whoever can start a process in the server's container, or as its service user
on a binary install: the operator of the installation. There is no HTTP
route and no console button. The commands use the server's own database and
Redis settings and nothing else.

## What the doctor checks

| Check | Passes when | Typical fix |
|---|---|---|
| Build | (reported) version, commit, build time, release channel, loaded extensions | |
| Configuration | the settings load and validate | correct the setting the detail names |
| Public URL | `APP_URL` is set and is an origin (https in production) | set it to the exact origin browsers and sensors use |
| Encryption key | `APP_ENCRYPTION_KEY` is set and is a valid key | restore the original value from your backup of the settings |
| Fingerprint key | `FINGERPRINT_KEY` is set and at least 32 characters | restore the original value |
| Keys to keep | (reported) `APP_ENCRYPTION_KEY`, `FINGERPRINT_KEY`, `SENSOR_KEY_PEPPER`: set or not set | never regenerate them on a running installation; back them up with the database |
| Database | PostgreSQL answers | check that it runs and that the `DB_*` settings match it |
| Database role | the API's role is not a superuser, may not create objects in the schema and does not own the audit tables | [least-privilege database roles](../deployment/database-roles.md) |
| Migrations | every migration of this build is applied and the schema is not dirty | run the release's migrations |
| Clock | this host and the database server agree within 5 seconds (fails from 60) | NTP on both hosts |
| Redis | Redis answers | check that it runs and that the `REDIS_*` settings match it |
| Certificate files | the files in `SYSTEM_TLS_CERT_FILES` and the sensor CA are more than 30 days from expiry (fails within 7) | renew the certificate |
| Public certificate | the certificate `APP_URL` serves is more than 30 days from expiry (fails within 7) | renew it at the gateway or load balancer |
| Disk space | every path in `SYSTEM_STORAGE_PATHS` has more than 20% free (fails below 10%) | free or add space |
| Backup | the backup status file reports a success in the last 26 hours | run and schedule the backup job |
| Service web, Service gateway | the configured health URL answers | check that container |
| Job queue | the oldest command waiting for a sensor is under an hour old, notifications leave within 15 minutes | bring a sensor that can run the work online |
| Stuck jobs | no scan run is past its deadline, no notification failed for good | restart the server; re-test the failing integration |
| Sensor heartbeats | at least one active sensor is online (counts by state) | check the sensors' hosts |
| Sensor versions | no active sensor is older than the minimum this build supports (counts) | upgrade those sensors |
| Audit chain | (reported) entries, chains, known link breaks, rebaselines on record | explain each break with the chain tools ([audit hash chain](../architecture/audit-hash-chain.md)) |

Notes on single checks:

- **Keys.** The doctor measures the keys; it never prints a key, a part of
  one or a digest of one.
- **Public certificate.** The doctor sends one `HEAD` request to `APP_URL`
  (no proxy, no redirects, 5 seconds) and reads the expiry date of the
  certificate it is served. A server that cannot reach its own public address
  gets "not checked" here, not a failure. `--offline` skips the request.
- **Backup, disk space, certificate files** read what the console's Health
  page reads (`SYSTEM_BACKUP_STATUS_FILE`, `SYSTEM_STORAGE_PATHS`,
  `SYSTEM_TLS_CERT_FILES`). An installation that records no backup status is
  reported as such, not failed.
- **Audit chain.** The count is of entries whose link to the entry before
  them does not hold. It is reported, not judged: the doctor does not fail on
  it and does not say whether a break is harmless. The server verifies entry
  contents hourly.

Exit code: `0` when no check fails (warnings do not fail), `1` otherwise, `2`
for a wrong option. `--json` prints the same result for scripts and
monitoring. `--timeout` (default `2m`) bounds the whole run; each SQL
statement is cut after 5 seconds.

## What the support bundle contains

`openctem-support-<UTC time>.tar.gz`, a gzip-compressed tar archive of plain
text files:

| File | Content |
|---|---|
| `README.txt` | what the archive is and how to inspect it |
| `manifest.json` | every file with its size and SHA-256, what was left out and why, and what a bundle never holds |
| `doctor.txt`, `doctor.json` | the doctor's result; error details are masked |
| `build.json` | version, commit, build time, release channel, loaded extensions, Go runtime, OS and architecture |
| `config.json` | every registered setting as set / not set. A value is written only for numbers, durations, booleans, enumerations and seven settings whose value is one of a few fixed words (`APP_ENV`, `LOG_LEVEL`, `LOG_FORMAT`, `AUTH_PROVIDER`, `SIGNUP_MODE`, `STORAGE_PROVIDER`, `DB_SSLMODE`). No secret, URL, host name, path or list is ever written, and a variable the server does not know is not listed at all |
| `database/server.json` | PostgreSQL version, database size, session count |
| `database/tables.json` | per table: size, estimated row count, dead rows, last vacuum and analyze, scan counts |
| `database/indexes.json` | per index: size, validity, scan count |
| `database/activity.json` | sessions by state; for statements running longer than 30 seconds, their shape: every string, number and comment is removed (`SELECT id FROM assets WHERE name = ?`) |
| `database/migrations.json` | applied migrations: version, file name, time |
| `queue.json` | queue depths by capability and priority, sensor counts by state and version, feed progress |
| `logs/server.log` | the log lines of the period, masked (below); present only when logs were given |

### What it never contains

Database rows of any table; finding titles, descriptions and evidence; asset
names, addresses and host names; user names and e-mail addresses;
organization names; uploaded files; keys, passwords, tokens and connection
strings. The database statistics come from PostgreSQL's catalog and
statistics views only. The only reads of application tables are aggregate counts:
queue entries, scan runs, notifications, sensors by state and version, audit
chain entries.

### How the logs are masked

Every log line is masked before it is written:

- E-mail addresses, IPv4 and IPv6 addresses, host names (any dotted name that
  is not a file name), tokens, JSON Web Tokens, cookies, authorization
  headers, private keys, connection strings, credentials in URLs, query
  strings, long hex and base64 strings.
- In a structured line (JSON or `key=value`), the whole value of every field
  whose name says it holds an identity, a target, a credential, a body or
  evidence (`email`, `user_name`, `tenant_name`, `asset_name`, `host`,
  `target`, `remote_addr`, `request_body`, `headers`, `evidence`, ...).
- In messages and error texts, the row values PostgreSQL prints in an error
  detail and every quoted string that is not a table, column or constraint
  name.

A masked value looks like `[email:1a2b3c4d]`. The same value gets the same
mark everywhere in one bundle, so a problem can be followed through the logs
without the value. The mark is made with a random key that exists only while
the bundle is written: it cannot be turned back into the value, not even for
a short value such as an IP address, and marks of two bundles do not match.

Identifiers the platform generates (UUIDs, request ids) stay readable: they
name no one and nothing outside your database.

**The limit of masking.** The rules know formats and field names. A name
typed into free text with nothing around it ("the Payroll import failed")
has no format to recognise. The server's own messages put such values in
fields, where they are masked, but read the log before you send it, and use
`--no-logs` (or leave out `--logs`) when in doubt.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--since` | `24h` | keep log lines newer than this (a line without a time follows the line before it) |
| `--max-size` | `20M` | largest archive (256K to 200M); the oldest log lines are cut to fit |
| `--output` | `openctem-support-<time>.tar.gz` in the current directory | the file to write, new and readable by its owner only; an existing file is never replaced; `-` writes the archive to standard output |
| `--logs` | none | a log file to include after masking; `-` reads standard input (at most 2 GiB are read) |
| `--offline` | off | skip the request to the public URL |
| `--timeout` | `2m` | stop after this long |

The command prints every file it wrote into the archive with its size, every
note about what was left out, and where the archive is. It exits `0` when the
archive was written, whatever the doctor found.

## Inspect the bundle before you send it

```bash
tar -xzf openctem-support-20261117T101500Z.tar.gz
cat openctem-support/README.txt
cat openctem-support/manifest.json           # the list, the notes, what is never included
less openctem-support/doctor.txt
less openctem-support/config.json
less openctem-support/logs/server.log
grep -rn 'example.com' openctem-support/     # search for your own names: there should be no match
```

Every file is plain text. Delete any file or line you do not want to share
and re-pack the directory (`tar -czf`), or run the command again with
`--no-logs`. Then send the archive through the channel you agreed on with the
person helping you. A bundle is not secret the way a backup is, but it
describes your installation (versions, table sizes, sensor counts): share it
with the people who help you, not in a public issue.

## Related

- [Monitoring and alerting](monitoring.md): the same facts as metrics and alerts.
- [Least-privilege database roles](../deployment/database-roles.md)
- [Backup and restore](../deployment/backup-and-restore.md)
- [Encryption key rotation](../deployment/encryption-key-rotation.md)
- `server -check-config`: validate the settings without connecting to anything.
