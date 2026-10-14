-- A gate policy can fail dependency and image vulnerabilities on severity or
-- EPSS only when a fixed version exists (KEV still fails). Design:
-- docs/rfcs/RFC-051-ci-runner-identity-and-gate.md. Tens of rows per tenant;
-- a constant default (no table rewrite).
ALTER TABLE ci_gate_policies ADD COLUMN fixable_only BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN ci_gate_policies.fixable_only IS
    'true: a dependency or image vulnerability blocks on severity or EPSS only when a fixed version exists (KEV still blocks).';
