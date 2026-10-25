### Fixed: an expected pairing code can be cancelled, and pairing requests expire again

- Cancelling a pairing code made with "Expect a sensor" before any sensor used it returned an error.
- When such a code expired unused, the periodic pairing sweep failed and rolled back, so from then on no pairing request expired, no unconfirmed key was revoked and old requests were never purged (the API logged `sensor pairing sweep failed`). Reads already checked each expiry, so no expired code could be used.
- Migration `003423_sensor_pairings_key_check_closed_states` lets a cancelled or expired request have no sensor key; open and approved requests keep their key rule. Safe on populated tables (the new check is weaker than the old one).
