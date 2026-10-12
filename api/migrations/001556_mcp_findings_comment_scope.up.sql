-- The MCP write scope for finding comments maps to findings:comment
-- (split from findings:write): mcp:findings.write is renamed
-- mcp:findings.comment in stored grants, pending requests and organization
-- MCP policies. A connection keeps exactly the ability it had (comments).
UPDATE mcp_oauth_grants
   SET scopes = array_replace(scopes, 'mcp:findings.write', 'mcp:findings.comment')
 WHERE 'mcp:findings.write' = ANY (scopes);

UPDATE mcp_oauth_requests
   SET scopes = array_replace(scopes, 'mcp:findings.write', 'mcp:findings.comment'),
       granted_scopes = array_replace(granted_scopes, 'mcp:findings.write', 'mcp:findings.comment')
 WHERE 'mcp:findings.write' = ANY (scopes) OR 'mcp:findings.write' = ANY (granted_scopes);

UPDATE tenants
   SET settings = jsonb_set(settings, '{mcp,scopes}',
       (SELECT jsonb_agg(CASE WHEN s = 'mcp:findings.write' THEN 'mcp:findings.comment' ELSE s END)
          FROM jsonb_array_elements_text(settings -> 'mcp' -> 'scopes') AS s))
 WHERE settings -> 'mcp' -> 'scopes' ? 'mcp:findings.write';
