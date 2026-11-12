### Added: AI clients can ask whether a target is in scope

- New read-only MCP tool `check_scope`: an AI application connected to the platform asks whether a domain, IP, CIDR or URL may be tested at an intensity (passive, active or intrusive) and gets the same answer a scan would, from the organization's scope entries. The answer is `allowed`, `passive_only` or `refused`, with reason codes and a hint for the person; a refusal says it is the platform's decision and that variations are refused too.
- The tool never widens a scope and never lists scope entries or deny-list contents. A lookup error refuses. A target covered only by a bug-bounty program rule is allowed only for a member of that program who names it. Each connection is rate limited, and the audit trail stores the target as a digest.
- New OAuth scope `mcp:scope.read` (permission `attack_surface:scope:read`), offered with the other read scopes and shown on the consent page.
