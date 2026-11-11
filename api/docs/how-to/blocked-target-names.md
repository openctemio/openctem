# Blocked target names and exceptions

For platform owners. Design: RFC-154 (blocked target names); how the checks
run: the scope guardrails architecture page (`docs/architecture/scope-guardrails.md`).

The platform refuses some targets for every organization, whatever its scope
says. Open **Scanning > Platform scanning > Blocked names** in the console.

## What you can change

- **Block government and military names** (on by default): names such as
  `*.gov`, `*.mil`, `gov.xx`, `mil.xx` and `gouv`, `gob`, `go` or `govt` under
  a country code. Leave it on. To let one organization test one such name,
  grant an exception instead (below). Turning it off lets every organization
  add such names; the page then shows a standing warning, the change is in the
  admin audit log and every administrator is e-mailed.
- **Also blocked on this installation**: your own names, one per line (the
  names under each are blocked too). Names in `SCOPE_DENY_EXTRA` are shown
  read-only and stay blocked; change them on the server.
- **Longest exception**: how many days an exception may last (default 365, at
  most 1095).

## What you cannot change

Loopback, link-local and cloud metadata addresses, "this network", the whole
address space, public suffixes (`com.vn`, `co.uk`, ...), shared provider
domains as wildcard roots (`*.amazonaws.com`, ...) and ranges larger than
`SCOPE_MAX_PUBLIC_CIDR_V4/V6` are always refused. They are not on this page.

## Grant an exception

1. Get the organization's **written authorisation** to test the name: a bug
   bounty program's published scope, a contract, or a letter from the owner of
   the domain. Keep it; you will reference it.
2. Click **Grant exception**. Pick the organization, type the domain
   (`portal.example.gov.xx`), tick **Also the names under it** only when the
   authorisation covers them (a wildcard entry such as
   `*.portal.example.gov.xx` needs it), type the reference to the
   authorisation, the expiry date and the reason, and enter your authenticator
   code.
3. On a hosted service (`MANAGED_SERVICE`) another platform owner approves it
   under **Security > Approvals**; then grant it again.
4. Tell the organization. It adds the name to its scope as usual: domain proof
   when the platform requires it, approvals, step-up and scan governance all
   still apply.

An exception covers one organization and one name. It never helps another
organization, never opens the parent domain or other names, and never lifts
your own blocked names. Organizations never see each other's exceptions.

**Extend** sets a new expiry (an expired exception comes back). **Revoke**
ends it at once: the organization's scope entries for the name stop covering
it and scans of it are refused. An expired exception is refused when an entry
is added and before every scan, without any job.

## Legal note

Scanning a government or military system without permission is a crime in
many countries. You, the operator of this installation, are responsible for
verifying that the organization holds a valid written authorisation for every
name you grant, for the whole period of the exception. Record the reference
precisely; it is kept in the admin audit log with your name, the reason and
the expiry.

## What organizations see

A refused entry says: "Government and military domains are blocked on this
installation. Your platform administrator can grant an exception." Nothing
else about the policy or other organizations is shown.
