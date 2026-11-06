-- Platform-side per-host politeness for workflow chunks (research/49
-- §3.12.3 item 3).
--
-- A workflow step is cut into chunks that any eligible sensor may claim, so
-- two sensors could hit the same host at once (a port scan and an HTTP probe
-- of one host, or two runs). commands.host_keys, new, lists the hosts an
-- active chunk sends traffic to (lower-case host names and addresses; NULL
-- for passive work and for every other command). A command with host keys is
-- claimable only while no other acknowledged or running command of the same
-- tenant holds one of its keys; the claim serializes on the keys with
-- transaction advisory locks. A lease that runs out, a release or a finish
-- frees the hosts at once: only acknowledged and running commands count.
--
-- A nullable column and a partial index over active commands that carry
-- keys (none when this runs): no table rewrite, no backfill.

ALTER TABLE commands
    ADD COLUMN IF NOT EXISTS host_keys text[];

CREATE INDEX IF NOT EXISTS idx_commands_active_host_keys
    ON commands USING gin (host_keys)
    WHERE host_keys IS NOT NULL AND status IN ('acknowledged', 'running');

COMMENT ON COLUMN commands.host_keys IS 'Hosts an active workflow chunk sends traffic to; while it is acknowledged or running, no other command of the tenant with one of these keys is claimed. NULL: no per-host limit.';
