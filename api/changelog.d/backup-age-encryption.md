### Security: backup.sh can encrypt every backup file with age and records failures

- `deploy/backup.sh`: set `BACKUP_AGE_RECIPIENT` (an age public key or a recipients file) and the database dump, volume archives, gateway CA and `.env` are written as `.age` files with no plaintext left behind, also after a failed run. `verify` and `restore` decrypt with `BACKUP_AGE_IDENTITY`. Without a recipient the script prints a loud warning on every run.
- `.env` is now stored in its own archive (`env.tar.gz`); the `signer-keys` and `signer-state` volumes are backed up when they exist and restored from the backup.
- The script runs with `set -E`, so a failure inside a volume archive now writes exit code 1 to the status file and raises BackupFailed at once.
