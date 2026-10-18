### Security: suspend an organization or block an account from the console

- Console > Organizations can suspend an organization and lift the
  suspension; Console > Users can block an account platform-wide and unblock
  it. Each needs ops_admin or super_admin, a fresh authenticator code and a
  reason, and writes a critical admin audit row. Nothing is deleted.
- A suspended organization is refused to every credential from the next
  request on: session tokens (and their mint and refresh), API keys, MCP
  tokens, sensor keys, SCIM tokens, CI run tokens and inbound Jira and GitHub
  webhooks answer 403 `ORGANIZATION_SUSPENDED` ("This organization is
  suspended — contact support"). Its live connections close and its
  scheduled work (scheduled scans, reports, retests, syncs, sweeps, command
  claims) is skipped. One access gate decides, behind a shared cache the
  console overwrites on every change, and it fails closed.
- A blocked account cannot sign in, its sessions end, and its API keys and
  MCP tokens stop working; a profile save can no longer lift the block.
- Migration `tenant_suspension_user_block` adds `tenants.status` (default
  `active`) with who suspended it and why, and who blocked an account and why.
