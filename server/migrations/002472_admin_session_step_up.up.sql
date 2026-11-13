-- A console session remembers its last step-up confirmation, so one fresh
-- code covers the protected actions of the next few minutes (the window is
-- enforced in code). admin_sessions is small: a nullable column without a
-- default is a catalog-only change.
ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS step_up_at timestamptz;
