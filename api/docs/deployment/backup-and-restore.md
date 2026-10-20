# Off-host backups and point-in-time recovery (Docker Compose)

`deploy/backup.sh` writes a daily dump to the same host. That protects against a bad upgrade or a
deleted row, not against losing the disk or the host, and it can lose up to a day of data. The
optional overlay `deploy/docker-compose.backup.yml` adds:

- **WAL archiving**: every finished write-ahead-log segment goes to the repository, so the
  database can be recovered to any moment, not only to the last dump.
- **Full and differential backups** (weekly full, daily differential) taken from the running
  database, with retention.
- **A target of your choice**: S3-compatible storage (AWS S3, Cloudflare R2, MinIO, others),
  an SFTP host, or a local path (an external disk or a mounted share).

It is **off by default**: without the overlay the stack is unchanged. The tool is
[pgBackRest](https://pgbackrest.org) (MIT license); the choice is explained at the end.

| | |
|---|---|
| RPO | `BACKUP_ARCHIVE_TIMEOUT` (300 s by default: an idle segment is closed after at most 5 minutes) plus upload time: about 5 to 6 minutes. A busy database ships segments sooner. |
| RTO | download and unpack of the newest full and differential backup, plus WAL replay. Measured in the drill ([Drill](#drill)); it grows with database size and bandwidth, so time your own. |
| Scope | the database. Uploaded files, the job-signer volumes, the gateway CA and `.env` stay in `backup.sh`; keep running it. Point-in-time recovery does not replace those. |
| Retention | `BACKUP_RETENTION_FULL` full backups (4) and `BACKUP_RETENTION_DIFF` differential backups (7); WAL is kept for the oldest retained full backup. State this in your privacy policy: erased personal data stays in backups until it ages out. |

## What is protected, and from whom

- Everything is encrypted with AES-256 **on this host, before upload**. Whoever reads the
  bucket, the SFTP host or the disk sees only ciphertext. The key is the file
  `backup-secrets/cipher_pass`. **Losing it makes every backup unreadable: keep a copy
  off this host** (a password manager, an offline note). Do not store it in the same bucket.
- Credentials are **files** under `backup-secrets/` mounted read-only, never environment variables
  (an environment variable shows in `docker inspect` and process listings). The entrypoint
  copies them to an in-memory filesystem the database user can read, only inside the two backup containers.
- The key on the host can write and read the repository. Make it unable to delete (below) so that
  a compromised host cannot wipe the history; retention then runs from a lifecycle rule or a
  separate administrator key instead of from the host.
- A repository that is only on this host (`local` on the same disk) is not a backup against host loss.

## Turn it on

1. Choose a target and create its credentials (per-provider sections below).
2. Create the secrets directory next to the compose files (it is ignored by git):

   ```bash
   cd api/deploy
   install -d -m 0700 backup-secrets
   openssl rand -base64 32 | tr -d '\n' > backup-secrets/cipher_pass   # then copy it off this host
   printf '%s' '<access key id>'     > backup-secrets/s3_access_key      # target s3
   printf '%s' '<secret access key>' > backup-secrets/s3_secret_key      # target s3
   chmod 0600 backup-secrets/*
   ```

3. Put the target in `.env` (see each provider) and start with the overlay:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.backup.yml up -d --build
   ```

   `COMPOSE_FILE=docker-compose.yml:docker-compose.backup.yml` in `.env` makes this the default for
   every later `docker compose` command (and for `backup.sh`).
   Enabling archiving restarts PostgreSQL once (a brief outage: do it in a maintenance window).
   The `postgres` image is rebuilt from the same PostgreSQL release plus pgBackRest.

   If your data directory was created by the Alpine image (`postgres:17-alpine`; the stack in
   this directory uses the Debian image), build on that one instead:
   `BACKUP_POSTGRES_IMAGE=postgres:17-alpine`, `BACKUP_IMAGE_TAG=17-alpine`, `BACKUP_PG_UID=70`.
   Never switch an existing data directory between the two flavours: the C library differs, and
   with it text sort order, which can corrupt indexes. `DRILL_POSTGRES_IMAGE=postgres:17-alpine
   deploy/backup/drill.sh` rehearses the Alpine build.

4. Watch the first run: `docker compose logs -f backup`. It creates the repository, checks
   archiving end to end, and takes the first full backup. `docker compose exec backup
   gosu postgres pgbackrest --stanza=openctem info` lists the backups.

Until the repository exists, PostgreSQL cannot archive and keeps the WAL in its data directory.
That is normal for the first minute; if it lasts, fix the target (logs of `backup`) quickly: a long
archive outage fills the disk. Alert on `pg_stat_archiver.failed_count` growing and on
`BackupStale` (the existing alert covers `backup.sh`).

Settings (`.env`; defaults in parentheses):

| Variable | Meaning |
|---|---|
| `BACKUP_TARGET` | `s3`, `sftp` or `local`. The overlay refuses to start with `none` or unset: leave the overlay out to keep backups off. |
| `BACKUP_RETENTION_FULL` (4), `BACKUP_RETENTION_DIFF` (7) | how many to keep |
| `BACKUP_TIME` (02:30), `BACKUP_FULL_DAY` (0 = Sunday) | daily start (UTC) and the weekday of the full backup |
| `BACKUP_ARCHIVE_TIMEOUT` (300) | seconds after which an idle WAL segment is closed (RPO) |
| `BACKUP_PROCESS_MAX` (2) | parallel upload/compression workers |
| `BACKUP_SECRETS_DIR` (`./backup-secrets`) | directory with the secret files |
| `BACKUP_POSTGRES_IMAGE`, `BACKUP_IMAGE_TAG`, `BACKUP_PG_UID` | base image, local image tag and the postgres user id (999 Debian, 70 Alpine) |
| `BACKUP_STANZA` (openctem) | repository name; one stack per repository path |

## Target: AWS S3

```env
BACKUP_TARGET=s3
BACKUP_S3_ENDPOINT=s3.eu-west-1.amazonaws.com
BACKUP_S3_REGION=eu-west-1
BACKUP_S3_BUCKET=my-openctem-backups
BACKUP_S3_PATH=openctem            # a folder inside the bucket
```

Create a private bucket (block public access, versioning on, optionally Object Lock) and an IAM user
used only by this host:

```json
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:ListBucket","s3:GetBucketLocation"],"Resource":"arn:aws:s3:::my-openctem-backups"},
 {"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::my-openctem-backups/openctem/*"}]}
```

This key cannot delete objects, so retention does not remove anything from the host: pgBackRest
expiry deletes by itself and will log errors. Choose one: either grant `s3:DeleteObject` (simple;
a rooted host can then wipe the bucket, so combine with versioning or Object Lock), or keep the
key write-only and prune with a bucket **lifecycle rule** (expire under `openctem/` after the
retention window plus a margin of one full-backup interval) and set `BACKUP_RETENTION_FULL` high
enough that the tool does not try. With Object Lock in compliance mode, a deleted object stays
until its retention ends. Use `BACKUP_S3_URI_STYLE=host` (default).

## Target: Cloudflare R2

```env
BACKUP_TARGET=s3
BACKUP_S3_ENDPOINT=<account id>.r2.cloudflarestorage.com
BACKUP_S3_REGION=auto
BACKUP_S3_BUCKET=my-openctem-backups
BACKUP_S3_URI_STYLE=path
```

Create the bucket, then an **R2 API token** limited to that bucket with *Object Read & Write*; its
access key id and secret go in `s3_access_key` and `s3_secret_key`. R2 charges no egress fee, which
makes restore drills cheap. Use a lifecycle rule for expiry, and bucket lock rules if your plan offers
them. Data stays in the jurisdiction you chose for the bucket.

## Target: MinIO (or another S3-compatible server)

```env
BACKUP_TARGET=s3
BACKUP_S3_ENDPOINT=minio.internal.example:9000
BACKUP_S3_BUCKET=openctem
BACKUP_S3_URI_STYLE=path
```

pgBackRest talks **TLS only** to S3. Give the server a certificate; for a private CA, put the CA
certificate in `backup-secrets/s3_ca.pem` (it is used automatically). `BACKUP_S3_VERIFY_TLS=n` exists
for a throwaway lab and must not be used in production. Use a MinIO user whose policy allows only
this bucket, and turn on object locking (it must be enabled when the bucket is created) for
immutability.

## Target: another host over SFTP

```env
BACKUP_TARGET=sftp
BACKUP_SFTP_HOST=backup.example.net
BACKUP_SFTP_PORT=22
BACKUP_SFTP_USER=openctem
BACKUP_SFTP_PATH=/srv/backups/openctem
BACKUP_SFTP_HOST_FINGERPRINT=<64 hex characters>
```

On the backup host create the user and the directory (it needs write access there only). Generate a
dedicated key **pair** on any machine, install the public half in the user's `authorized_keys`,
and put the private half in `backup-secrets/sftp_private_key` (PEM/OpenSSH; a passphrase, if any, in
`sftp_key_passphrase`). The host key is pinned, never trusted on first use: compute its fingerprint
from a channel you trust (the host's console, not the network path the backups will use):

```bash
ssh-keyscan -t ed25519 backup.example.net 2>/dev/null | awk '{print $3}' | base64 -d | sha256sum | cut -d' ' -f1
```

For immutability use a host or filesystem snapshots that the SFTP user cannot remove (for example
ZFS snapshots taken on the backup host), and an account restricted to its own directory.

## Target: a local path

```env
BACKUP_TARGET=local
BACKUP_LOCAL_PATH=/mnt/backup-disk/openctem   # a host directory, owned by uid 999
```

Without `BACKUP_LOCAL_PATH` a Docker volume on this host is used (useful only for a trial). For
protection against host loss the path must be a different disk or a network mount.

## Restore

The recovery is run by the `backup` service's image against the database volume, with the
database stopped. **Take a copy of the damaged data first if there is any chance it is still needed**
(`docker run --rm -v <project>_postgres-data:/d -v $PWD:/o alpine tar czf /o/pgdata-before-restore.tgz -C /d .`).

Latest state (disk lost, the host replaced):

```bash
docker compose stop gateway web console api postgres backup   # the services your stack runs
docker compose run --rm --no-deps backup restore --delta
docker compose up -d
```

`--delta` reuses files already in the data directory and replaces the changed ones; on an empty
volume it is a plain restore. On a new host: install the stack, put the same `backup-secrets/`
(the same `cipher_pass`) and the same `.env` in place (`APP_ENCRYPTION_KEY` decrypts stored
credentials; it comes from `backup.sh`'s `env.tar.gz`), then run the three commands above.
PostgreSQL replays WAL to the end of the archive on start.

### Point in time (undo a bad delete or migration)

Pick a moment just before the damage, in UTC, then:

```bash
docker compose stop gateway web console api postgres backup
docker compose run --rm --no-deps backup restore --delta \
  --type=time "--target=2026-10-20 14:02:00+00" --target-action=promote
docker compose up -d postgres      # replays WAL up to the target and opens
docker compose exec postgres psql -U "${DB_SUPERUSER:-openctem}" -d "${DB_NAME:-openctem}"   # look before you start the services
docker compose up -d
```

`--target-action=promote` opens the database as soon as the target is reached. Check the data
before starting the API. After any point-in-time restore the history forks: the next archived
segments start a new timeline, and the `backup` service takes a new full backup on its next run
(`docker compose exec backup gosu postgres pgbackrest --stanza=openctem backup --type=full` to do it now).
Rows written after the target time are gone for good unless you restore again to a later time.

## Drill

Do it monthly, and after changing the target or the key. A backup nobody restored is a hope.

1. **Scratch restore of the real repository** (does not touch the live database): restore the
   newest state into a throwaway volume and start a database on it that does not archive:

   ```bash
   docker volume create drill-data
   docker compose run --rm --no-deps -v drill-data:/var/lib/postgresql/data backup restore \
     --type=time "--target=$(date -u +'%Y-%m-%d %H:%M:%S+00')" --target-action=promote
   docker compose run --rm --no-deps --name drill-pg -v drill-data:/var/lib/postgresql/data \
     -e POSTGRES_USER="${DB_SUPERUSER:-openctem}" --entrypoint bash postgres \
     -c '. /usr/local/bin/render-conf.sh; render_conf; exec docker-entrypoint.sh postgres -c archive_mode=off'
   # in another shell: compare row counts of a few tables with the live database, note the time it took
   docker rm -f -v drill-pg; docker volume rm drill-data
   ```

   The database starts with `archive_mode=off`, so the drill never writes into the repository.

2. `docker compose exec backup gosu postgres pgbackrest --stanza=openctem verify` reads every file in the
   repository and checks it against its checksum (the `backup` service also runs it after each
   full backup).

3. **Self-contained rehearsal** (a lab, no real credentials): `deploy/backup/drill.sh` starts a
   throwaway S3-compatible server and PostgreSQL in containers named `bkp-drill-*`, enables
   archiving, takes a base backup, writes rows, marks a time, writes more, restores to the marked time
   into a fresh container and compares row counts, then removes everything it created. It needs
   Docker, `openssl` and `bc`; all credentials are generated for the run.

Result of `drill.sh` on a development host (PostgreSQL 17, pgBackRest 2.59, an empty database plus
1500 rows, MinIO over TLS and, separately, an SFTP server): 8 WAL segments archived, 0 failed; with the
marker after 1200 of 1500 rows, the restore to the marker opened with exactly 1200 rows. Download and
unpack took about 1.3 s and the database was open and promoted 3.7 s after the restore started. A
real database is far larger: the RTO is dominated by bandwidth and WAL replay, so measure it with your own drill.

## Why pgBackRest

pgBackRest supports S3-compatible storage (including R2 and MinIO), Azure, Google Cloud Storage, SFTP
and POSIX paths, with parallel transfer and compression. It was chosen because:

- **Encryption is built in** (AES-256 with a passphrase) and covers backups and WAL.
- **Retention and expiry** are one policy (full and differential counts that also prune WAL).
- **Verification**: `check` proves archiving works end to end and `verify` checks every file in the
  repository; differential backups and delta restore are native.
- **Asynchronous parallel archiving** with a spool keeps a commit from waiting on the network.
- The package comes from the PostgreSQL project's own apt source in the official image: one
  `apt-get install`, no extra binary to pin. License: MIT.

The cost: a backup reads the database files, so the backup service shares the data volume and the
socket directory with PostgreSQL (it runs the same image).

The Ansible kit (`openctem-ansible`, role `backup`) has its own continuous archiving that ships age-encrypted,
signed WAL with rclone to a bucket that the host cannot delete from; use that for host-level installs.
This overlay is for Compose installs that manage their stack directly.
