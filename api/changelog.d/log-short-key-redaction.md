### Fixed: logs no longer hide ordinary fields that contain "iv"

- The log redactor matched short sensitive keys ("iv", "pwd", "dob", "jwt", "ssn", "dsn") anywhere inside an attribute key, so fields such as `diverged`, `active`, `archived` or `live` were logged as `[REDACTED]`. A sensitive key of three letters or fewer now matches only as a whole segment of the key (`aes_iv`, `user.dob`); longer keys still match anywhere.
- The scope-ledger sync warning says what the job signer does with jobs for scope its ledger does not hold: in audit mode they are signed and logged (nothing is refused yet); in enforce mode they are refused. The warning carries `ledger_mode`, and the number of diverged entries is readable again.
