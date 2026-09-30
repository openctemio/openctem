-- Revert Migration 000225: drop platform admin console authentication.
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS admin_credentials;
