### Added: optional off-host backups and point-in-time recovery for the Compose stack

- New overlay `deploy/docker-compose.backup.yml` (off by default; nothing changes without it) adds WAL archiving through pgBackRest and a `backup` service taking weekly full and daily differential backups, encrypted with AES-256 on the host before upload, with retention and a verify after each full backup.
- `BACKUP_TARGET` selects S3-compatible storage (AWS S3, Cloudflare R2, MinIO), an SFTP host or a local path. Credentials and the encryption key are files under `backup-secrets/`, never environment variables.
- Documented in `docs/deployment/backup-and-restore.md`: per-provider setup, RPO and RTO, full restore, point-in-time restore and a restore drill; `deploy/backup/drill.sh` runs the drill on throwaway containers.
- Enabling archiving restarts PostgreSQL once.
