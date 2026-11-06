### Added: deep subdomain enumeration once for every new root domain

- The first `enumerate.subdomains` coverage pass of a new root (a `domain` asset under an active scope entry whose enumeration never succeeded) runs once at deep depth: the medium wordlist pack (`wordlists-m`) with the learned labels and their permutations. The root then returns to the weekly standard pass (`wordlists-s`).
- "Once" is the first success of the pair in the coverage ledger, so restarts and replicas never repeat it. At most 10 roots go in one deep run, ahead of the steady batch; one coverage run per capability is active at a time.
- A deep pass that fails 3 times in a row falls back to standard; without a stable `wordlists-m` the pass runs at standard depth.
- Upgrade note: roots never enumerated so far get the deep pass once after the upgrade; roots already enumerated keep the weekly standard pass. No migration.
- Security: which roots may be enumerated is unchanged (scope entry, full dispatch gate, claim-time re-check, domain proof on shared sensors); onboarding state is per tenant.
