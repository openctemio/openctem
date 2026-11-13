-- Per-domain sign-up policy of a verified SSO domain (RFC-104): what an
-- organization's claim on its domain does to new accounts on it. Every effect
-- is off by default and applies only while the claim is verified and
-- unambiguous (status verified, purpose sso, no claim_conflict).
--
-- join_policy: off | approval | auto. With approval, a verified holder of an
--   address on the domain may ask to join; with auto, joins at once.
-- join_role: viewer | member, the role of people who join by domain (never an
--   administrator).
-- discoverable: show the organization to verified holders of the domain in
--   onboarding.
-- sso_required: refuse password and social sign-up for addresses on the
--   domain; they sign in through the organization's SSO.
-- block_new_workspaces: accounts on the domain may not create organizations.
-- include_subdomains: the effects also cover addresses on subdomains.
-- capture_notified_at: when existing accounts on the domain were told the
--   organization now manages it (once, when sso_required or
--   block_new_workspaces first turned on).
--
-- verified_domains holds a few rows per organization: constant defaults add
-- the columns without a table rewrite and the checks validate at once.

ALTER TABLE verified_domains
    ADD COLUMN join_policy text NOT NULL DEFAULT 'off',
    ADD COLUMN join_role text NOT NULL DEFAULT 'viewer',
    ADD COLUMN discoverable boolean NOT NULL DEFAULT false,
    ADD COLUMN sso_required boolean NOT NULL DEFAULT false,
    ADD COLUMN block_new_workspaces boolean NOT NULL DEFAULT false,
    ADD COLUMN include_subdomains boolean NOT NULL DEFAULT false,
    ADD COLUMN capture_notified_at timestamp with time zone,
    ADD CONSTRAINT chk_verified_domains_join_policy CHECK (join_policy IN ('off', 'approval', 'auto')),
    ADD CONSTRAINT chk_verified_domains_join_role CHECK (join_role IN ('viewer', 'member'));
