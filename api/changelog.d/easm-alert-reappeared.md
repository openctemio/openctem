### Added: exposures that disappear and return alert again as "reappeared"

- An active EASM exposure that is not seen for longer than the organization's alert fingerprint lifetime and is then seen again is announced again, with `reason` `reappeared`. The lifetime is `reappear_after_days` in `/easm/settings` (7 to 365, default 30; 0 restores the default). Each organization has its own lifetime and its own history; resolved and accepted exposures stay quiet.
