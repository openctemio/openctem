-- Step-up re-authentication for sensitive actions
-- (docs/architecture/step-up-reauth.md).
--
-- step_up_at is when the signed-in user last proved their identity again
-- (TOTP when enrolled, else the password) inside this session. A sensitive
-- route accepts the request while the later of created_at (the sign-in) and
-- step_up_at is within the step-up window. The value lives on the server and
-- belongs to one session, so a step-up in one browser does not unlock another.
--
-- Nullable with no default: adding it is a catalog-only change and does not
-- rewrite or long-lock the table.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS step_up_at TIMESTAMPTZ;

COMMENT ON COLUMN sessions.step_up_at IS
    'Last successful step-up re-authentication in this session (NULL = none since sign-in)';
