# RFC-154: Blocked target names and exceptions

| | |
|---|---|
| Status | Implemented (2026-11-11) |
| Scope | api (scope guardrails, platform settings, console routes, dispatch gate), console (Scanning > Platform scanning), web (scope refusal text) |
| Architecture | [scope-guardrails.md](../architecture/scope-guardrails.md), [active-probe-gate.md](../architecture/active-probe-gate.md) |
| Related | RFC-054 §8 (scope guardrails), RFC-079 (console platform settings), RFC-134 (platform permissions) |

## 1. Problem

RFC-054 §8.2 refuses every government and military name (`*.gov`, `*.mil`,
`gov.<cc>`, `mil.<cc>`, `gouv`, `gob`, `go`, `govt` under a country code, and
a few names such as `gc.ca`) as a scope entry and at dispatch. The rule was
compiled in. An organization that is authorised to test such a name (a bug
bounty program whose scope lists a government domain, a government body
running its own installation) could not add it, and the refusal said
"contact support", although nobody could change it. Everything an operator
manages belongs in the console.

## 2. Decisions

1. **One platform setting, "Blocked target names"** (`platform_settings`
   key `scope_blocked_names`, RFC-079 mechanism). It holds:
   - `government_rule`: the built-in government and military rule, **on by
     default** on new and existing installs. Nothing stored = on, so an
     upgrade changes nothing;
   - `names`: the operator's own blocked names, added to `SCOPE_DENY_EXTRA`.
     The environment entries stay in force and are shown read-only;
   - `max_exception_days`: the longest an exception may last (default 365,
     1 to 1095).
2. **Exceptions** (table `scope_name_exceptions`): one organization, one name,
   whether names under it are included, a reason, a reference to the written
   authorisation, who granted it, an expiry (required, at most
   `max_exception_days`) and a state (active, expired, revoked). An exception
   lifts **only the government and military rule**, only for that
   organization and only for that name (with `include_subdomains`, also the
   names under it). It never lifts the operator's own names, and it cannot
   name a government suffix itself (`gov.xx`, `*.gov`) or a public suffix.
3. **An exception widens nothing else.** The name still needs a scope entry
   through every rule of RFC-054: domain proof when the platform requires it
   (§8.1), approvals, step-up, scan governance, exclusions and the signer
   ledger.
4. **Hard-coded, never configurable:** loopback, link-local and cloud
   metadata addresses, "this network", the whole address space, public
   suffixes, shared provider apexes as wildcard roots and the public CIDR
   caps (environment only). The console says so next to the switch.
5. **Who.** Only a platform owner (new permission
   `platform.settings.scope_guardrails`, held by the owner role only) changes
   the setting or grants, extends or revokes an exception, each with a fresh
   console authenticator code and a reason. Any console reader sees them.
6. **Second approver on a hosted service.** When `MANAGED_SERVICE` is set,
   granting or extending an exception and turning the government rule off
   need a second platform owner through the existing four-eyes approvals
   (actions `scope_names.exception` and `scope_names.government_rule_off`).
   On a single-owner install the approvals mechanism's own fallback applies
   (the action runs with a critical audit row and every administrator told).
   A self-hosted install needs no second approver.
7. **Audit.** Every change writes a critical admin audit row (who, the
   organization, the name, the reason, the authorisation reference, the
   expiry, the values before and after) and e-mails every administrator.
8. **Enforced twice.** The guardrails check the exception when an entry is
   added (single add, bulk add, replacement, re-activation, bounty program
   import, EASM rule suggestions and confirm-scope, New scan wildcard
   targets) and again at dispatch (`Denies` in the ownership gate, the MCP
   scope check, the scope authority). An exception is judged against the
   clock at each check, so an expired one is refused at add and at dispatch
   without a job.
9. **Refresh.** Every copy of the guardrails reads one shared policy. A
   change applies at once on the replica that made it and within 15 seconds
   on the others. A policy that cannot be read keeps the last one read; at
   start-up that is the built-in rule on with no exceptions (fail closed).
10. **Refusal text.** A tenant whose entry hits the rule gets
    `400 GOVERNMENT_NAME`: "Government and military domains are blocked on
    this installation. Your platform administrator can grant an exception."
    Nothing about other organizations' exceptions is ever shown to a tenant.

## 3. Threat model

| Threat | Control |
|---|---|
| A tenant administrator grants itself an exception | no tenant route writes the policy or exceptions; console routes need `platform.settings.scope_guardrails` |
| A hijacked console session opens a government name | owner permission, fresh step-up, reason, critical audit, every administrator e-mailed; on a hosted service a second owner approves |
| An exception for one organization helps another | exceptions are keyed by organization; the guardrails consult only the caller's organization; a check without an organization applies none |
| An exception for `sub.example.gov.xx` opens `example.gov.xx` | exact match unless `include_subdomains`; a wildcard entry needs an exception that includes subdomains |
| An exception names a whole government suffix | refused: the name must sit below the government suffix and must not be a public suffix |
| A forgotten exception stays open | expiry required and bounded; judged at every check, also at dispatch |
| The rule is switched off quietly | audited critical, every administrator e-mailed, a standing warning on the console page |
| Tenants learn which organizations hold exceptions | the tenant refusal is generic; exceptions are console-only |

## 4. Simplest path

An owner opens Scanning > Platform scanning > Blocked names, clicks Grant
exception, picks the organization, types the name, the reason, the
authorisation reference and the expiry, enters the authenticator code. The
organization then adds the name to its scope as usual.

## 5. Not built

- No tenant-side request flow for exceptions: the organization asks its
  platform administrator out of band, with the written authorisation.
- No per-organization switch of the whole rule: an exception is per name.
- No new approvals system: the existing four-eyes approvals are reused.
