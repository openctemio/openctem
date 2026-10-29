-- admin_session_live: whether one console session is still usable (RFC-063,
-- support access). Support sessions live in the tenant plane (support_sessions,
-- written by the API's app role) but end with the console session that opened
-- them, and admin_sessions is readable only by the console role under the
-- least-privilege model (deploy/postgres/least-privilege-roles.sql). The API's
-- sweep and its "session open" signal need exactly one fact from it: is this
-- console session alive.
--
-- SECURITY DEFINER, owned by the schema owner, read only, STABLE, pinned
-- search_path. It takes a session id the caller already holds
-- (support_sessions.console_session_id) and returns one boolean: no token
-- hash, no administrator, no row ever leaves it, and it writes nothing. The
-- app role keeps no privilege on admin_sessions.
--
-- Live impact: a new function only.

CREATE OR REPLACE FUNCTION admin_session_live(p_session uuid, p_at timestamptz, p_idle_seconds double precision)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.admin_sessions c
        WHERE c.id = p_session
          AND c.expires_at > p_at
          AND c.last_seen_at > p_at - make_interval(secs => p_idle_seconds)
    )
$$;
REVOKE EXECUTE ON FUNCTION admin_session_live(uuid, timestamptz, double precision) FROM PUBLIC;
COMMENT ON FUNCTION admin_session_live(uuid, timestamptz, double precision) IS
    'Support access: true when console session p_session is unexpired at p_at and was seen within p_idle_seconds; SECURITY DEFINER, read only, returns one boolean so the app role needs no privilege on admin_sessions.';
