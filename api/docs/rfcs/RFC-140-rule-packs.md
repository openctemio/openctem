# RFC-140: Detection rule packs (web fingerprints and sensitive information)

| | |
|---|---|
| Status | Accepted (2026-10-31). Rule kinds, engine, built-in packs, ingest wiring, run record and organization rules API shipped; the console page and the page monitoring hook follow |
| Scope | api (content packs, detection rule engine, ingest, exposures, technologies, organization rules API), docs |
| Architecture | [rule-packs.md](../architecture/rule-packs.md) |
| Related | RFC-061 (content packs), RFC-112 (asset technologies), RFC-138 (web page monitoring), [wordlists.md](../architecture/wordlists.md) (pinning and run record), [web-content-pipeline.md](../architecture/web-content-pipeline.md) |

## 1. Problem

The platform names the technologies of a web service only from what a probe reports, and it has no way
to notice a key, a token or an internal host name that a web response or a JavaScript bundle gives away.
Both are rules over web content: literal markers and patterns that name a product and its version, or
find a credential. Organizations also know their own products and their own key formats, which no
curated list holds.

## 2. Decisions

1. **Two new content kinds** on the content pack pipeline (RFC-061): `web-fingerprints` and
   `secret-rules`. A platform rule pack is linted (every rule validated, unique ids, no credential-shaped
   text), stored in canonical form, signed, pointed at by the `stable` channel and revocable, like every
   other platform pack. A rule pack is always T0: rules are data.
2. **Rules are data, never code.** A rule names locations to read (`body`, `url`, `title`, `header`,
   `cookie`, `favicon`, `script`), case-insensitive literal keywords and an RE2 pattern, and either the
   technology it detects (name, category, CPE template with `{version}`) or the class of secret it finds
   (category, severity). It cannot fetch, write or send anything; its only output is "this rule matched
   here".
3. **Evaluated on the platform, at ingest, before anything is stored.** Each web service of a report is
   turned into a document (URL, final URL, title, `Server` header, cookie names, favicon hash, the script
   paths the report found on its origin) and scanned with the organization's engine. No sensor, SDK or
   protocol change: the content is what reports already carry. A component that receives a raw web
   response (page monitoring captures, RFC-138) passes it to the same engine (`ScanDocument`) before it
   normalizes or masks it. Sensor-side evaluation is only considered for content the platform never
   receives.
4. **Keyword prefilter, then RE2 on windows.** All keywords of a location are indexed once; one pass over
   the text finds every hit; a pattern runs only on a window of 256 bytes around a hit of its own keyword.
   Body and script matchers must have a keyword. Short fields (title, header, URL, cookie name) are capped
   and read whole.
5. **Bounded cost.** Patterns: at most 512 bytes, a compiled program of at most 4,000 steps, at most 8
   groups, repeat bounds of at most 256, and no pattern that matches empty text. Documents: at most 1 MiB
   of body, 64 KiB of script paths and 2 KiB per field are read; at most 2,000 pattern runs, 50 matches
   and 100 ms per document; at most 64 hits per keyword. A budget that runs out stops the scan of that
   document and is logged with counts only.
6. **Secrets are masked inside the engine.** A match leaves the engine as a keyed fingerprint (HMAC-SHA256
   under a per-tenant key derived from the server secret; none without a key), a preview of at most four
   characters at each end, the length and the location (field, line, column). The value is never stored,
   logged, audited or returned, including by the rule test.
7. **Fingerprints become technologies** of the asset through the report: a match is added to the report
   asset's technologies before set reconciliation (a tool's own report of the same technology wins), then
   its source (`rules:<pack>@<version>` or `rules:organization`), category, CPE and confidence are
   recorded. A technology with a version or CPE also becomes a software component (RFC-112), so CVE
   matching uses it.
8. **Secrets become exposures** through the EASM exposure writer (alert policy, hourly budget, digest):
   `credential_leaked` for credentials, tokens and private keys, `sensitive_data_exposed` for internal
   host names, personal data and debug output. One exposure per rule, asset, URL and secret fingerprint;
   the details name the pack, version and digest.
9. **Organization rules are rows.** One row per rule (`tenant_content_rules`), the rule body validated
   exactly like a pack rule, versioned (`version` + sha256), switchable, audited, at most 200 per
   organization. They join only that organization's engine, under ids prefixed `org.`. An organization
   cannot upload a rule pack: only platform rule packs are evaluated.
10. **Pinned and recorded.** Platform packs: the `stable` channel per pack name. The built-in packs
    (`web-fingerprints-core`, `secret-rules-core`, written for this project) are installed on first start
    when the name has no stable channel, and never move an existing one. Every command-bound report
    records in `commands.content_pins.rules` the rule sets it was matched with (kind, scope, pack,
    version, digest, rule count).

## 3. Threat model

| Threat | Control |
|---|---|
| CPU exhaustion by a hostile or careless rule (ReDoS) | RE2 semantics (linear time, no backreferences or lookaround), pattern size, program, group and repeat limits, no empty matches, keyword prefilter with windows, per-document run, match and time budgets, 200 rules per organization |
| Rule poisoning to exfiltrate data | a rule has no I/O and no output besides a match; matched values leave only masked; an organization's rules run only on its own reports |
| Secret stored or logged in clear | masking inside the engine; exposures hold fingerprint, preview, length and location; logs hold counts; the test endpoint returns previews |
| Offline confirmation of a guessed secret | per-tenant keyed HMAC from the server secret; no fingerprint without a key |
| Cross-tenant access to organization rules | tenant from the token; every statement carries `tenant_id`; another organization's rule is 404; DB tests cover read, update, delete, list and the engine |
| Data scope | exposures and technologies are read through the existing scoped endpoints; rules are tenant configuration under `scans:content:read`/`scans:content:write` |
| Malicious platform pack | built-in packs are embedded files linted like any upload; imported packs go through lint, canonical form and the platform signature |
| Alert floods | match cap per document, exposure identity by fingerprint, EASM alert policy |
| Spoofed fingerprints (a site that lies in its `Server` header) | rule confidence (70 by default) on the technology; CVE matches from it keep their confidence |

## 4. Not chosen

- **Matching stored content later**: what the platform stores is already masked or normalized (evidence
  snippets, page monitoring text), and keeping raw responses to match later would store secrets.
- **Generating scanner templates from rules**: a second fetch of every target, and the scanner would send
  the raw value to the platform.
- **Organization rule packs (archives)**: a rule is small and edited one at a time; rows are easier to
  review, test and audit, and work for every sensor kind.

## 5. Status

- Shipped: kinds, lint, engine, built-in packs, ingest wiring, exposures, technologies, run record,
  `/api/v1/content-rules` (list with the platform packs in use, create, read, update, delete, test).
- Next: the console page (Scanning > Detection rules: list, editor, test panel) and the run page's rule
  sets; the page monitoring hook (`ScanDocument` on each raw capture); a fingerprint-only header
  allow-list (`x-powered-by`, `x-generator`) in sensor reports; per-profile pack pins.
