-- Re-verification policy (docs/architecture/step-up-reauth.md): an action the
-- organization asks for every time spends the session's latest proof of
-- identity. The column holds the timestamp of the proof last spent; NULL means
-- none was spent. Nullable, no default: adding it rewrites no rows.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS step_up_spent_at TIMESTAMPTZ;

COMMENT ON COLUMN sessions.step_up_spent_at IS
    'Timestamp of the proof of identity (sign-in or step-up) last spent by an every_time action; NULL when none was spent.';
