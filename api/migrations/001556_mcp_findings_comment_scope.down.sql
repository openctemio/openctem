UPDATE mcp_oauth_grants
   SET scopes = array_replace(scopes, 'mcp:findings.comment', 'mcp:findings.write')
 WHERE 'mcp:findings.comment' = ANY (scopes);

UPDATE mcp_oauth_requests
   SET scopes = array_replace(scopes, 'mcp:findings.comment', 'mcp:findings.write'),
       granted_scopes = array_replace(granted_scopes, 'mcp:findings.comment', 'mcp:findings.write')
 WHERE 'mcp:findings.comment' = ANY (scopes) OR 'mcp:findings.comment' = ANY (granted_scopes);

UPDATE tenants
   SET settings = jsonb_set(settings, '{mcp,scopes}',
       (SELECT jsonb_agg(CASE WHEN s = 'mcp:findings.comment' THEN 'mcp:findings.write' ELSE s END)
          FROM jsonb_array_elements_text(settings -> 'mcp' -> 'scopes') AS s))
 WHERE settings -> 'mcp' -> 'scopes' ? 'mcp:findings.comment';
