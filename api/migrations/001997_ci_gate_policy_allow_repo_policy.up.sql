-- Whether a repository's .openctem.yml may tighten the CI gate and request
-- exceptions (RFC-077 G-8). On by default; the strictest policy wins.
ALTER TABLE ci_gate_policies ADD COLUMN IF NOT EXISTS allow_repo_policy BOOLEAN NOT NULL DEFAULT TRUE;
