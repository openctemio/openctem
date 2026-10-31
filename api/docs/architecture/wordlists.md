# Wordlists: the first-party packs

Design: research/294 (decisions D1, D2 and O2) and research/344 (built-in packs, permutations,
organization lists). Pack store and delivery:
[content-packs.md](content-packs.md). This page describes the build that makes the curated
public lists and the manifest the platform checks on import.

## What is built

Two platform packs of kind `wordlist`, by size class:

| Pack | dns-labels | api-routes | params |
|---|---|---|---|
| `wordlists-s` | 5,000 | about 370 | about 190 |
| `wordlists-m` | 50,000 | about 11,000 | about 190 |

Web path and file lists are not in this release. Every source of them that was considered has
a license that is not on the allow-list (see "Licenses"), so none is bundled yet. They are added
by a `sources.yaml` change once a source with a permissive license is found. Class L follows with
the plan gate.

## The build

`api/cmd/wordlists-build` reads `api/cmd/wordlists-build/sources.yaml`:

1. Every upstream file is pinned by repository commit **and** by the sha256 of the file. The
   download is over https from `raw.githubusercontent.com` only, is capped at 32 MiB per file
   and is refused when the sha256 differs. Downloaded bytes are data: they are counted and
   compared, never executed.
2. A file is used only when its own license is on the allow-list. The license is decided per
   file from its upstream, not from the repository that hosts it, and `evidence` in
   `sources.yaml` says how it was established. Files that are left out are listed in
   `excluded` with the reason and in every pack's `NOTICE`.
3. Each line is normalised for the list's purpose (the same rules the sensor runtime applies):
   DNS labels are lower case, `[a-z0-9-]`, at most three dotted labels; paths are relative, with no
   scheme, host or `..`; parameter names match `[A-Za-z0-9_.\[\]-]{1,64}`. Invalid lines (a URL, a
   wildcard marker, NUL or control characters) are dropped.
4. The inputs of a list are merged by rank: an entry keeps its best position in any input, ties
   go to the earlier input, repeats are removed, and the first `cap` entries are kept.
5. The pack gets `wordlists.yaml` (per list: purpose, class, line count, sha256, and every
   source with url, commit, path and SPDX id) and `NOTICE` (every source with commit, file,
   license and copyright, then the excluded files).
6. The build lints the pack with the platform linter and checks the platform accepts the
   archive. The release asset is a deterministic tar.gz: the same pins give the same bytes
   (the release workflow builds twice and compares).

```
cd api
go run ./cmd/wordlists-build -out dist/wordlists
```

The workflow `.github/workflows/wordlists-release.yml` (manual, from `main`) publishes the packs as
assets of the release `wordlists-<release>` with a build provenance attestation. `release.json` in
the release carries the asset sha256 of each pack.

## Built-in packs

The packs of the current release are also embedded in the API
(`api/internal/app/contentpin/builtin/`: the two archives and `release.json`), so subdomain
enumeration works on a fresh install with no import and no internet access:

- At start the API installs each embedded pack whose name has **no `stable` channel**, through the
  same canonicalisation, lint and platform signature as an upload (source `upload`, source reference
  `builtin:<asset>`), and points `stable` at it. An existing `stable` channel is never moved: an
  administrator's import, or a deliberate older release, stands. A release an administrator revoked
  is not reinstated. Several replicas starting together are safe: the second finds the pack by name
  and version.
- The embedded files are the output of the build, and nothing else:
  `go run ./cmd/wordlists-build -out internal/app/contentpin/builtin`. A test checks each archive
  against `release.json` and the canonical digest, another that their release is the one
  `sources.yaml` names (a pin change must rebuild them), and the release workflow compares the
  published assets with the embedded bytes.
- To adopt a newer release on a running platform, import it (below) and move `stable`; the next API
  version also embeds it, but never moves a `stable` channel that exists.

## Import

A super admin imports each asset as a platform pack of kind `wordlist` with
`POST /api/v1/admin/content-packs/import` (https URL of the asset and its sha256; TOTP step-up,
a reason and an audit row, as for any platform pack) and then moves `stable` to it. An installation
without internet access uploads the asset instead (`POST /api/v1/admin/content-packs`).

Asset coverage runs `enumerate.subdomains` at standard depth, so it reads the `dns-labels` lists
of `wordlists-s`. If no such pack is on `stable` (the built-in one revoked and none imported), the
capability is paused with readiness reason `content_missing` ([asset-coverage.md](asset-coverage.md)).

## The list a job reads

A `dns-labels` request (the `dnsx-enum` tool's slot `labels`) is pinned at claim
([content-packs.md](content-packs.md)): the platform pack of the run's depth (standard `wordlists-s`,
deep `wordlists-m`) by digest, plus one list generated for the job and carried inline:

1. **Learned labels**: the labels of the organization's own active names under the root, and their
   parts split at `-` and at letter/digit boundaries, most frequent first.
2. **Permutations** of those labels, after them: numbered neighbors of a numbered label
   (`web09` gives `web10`, `web08`), numbered copies of a label ending in an environment word
   (`portal-uat` gives `portal-uat1`, `portal-uat2`), and base words crossed with the environment
   words the organization's names use (`dev`, `uat`, `staging`, ...; `dev`, `test`, `uat` and
   `staging` when they use none). At most 20,000, every one a valid DNS label, the same for the same
   names.

The sensor composes the inline list first and the pack after it into one file, without repeats and
within the depth's line cap.

## What the platform checks

On import, and on every tenant upload that carries one, the linter checks `wordlists.yaml`:

- A platform wordlist pack must have it; a tenant pack may omit it (its lists then have no
  declared purpose).
- Every file of the pack is described, and every description is true: the sha256, the line count,
  every entry valid and unique for the purpose.
- Every source has an https url, a 40-hex commit, a path and a license on the allow-list.
  ShareAlike licenses (CC-BY-SA) are allowed only when the manifest says `opt_in: true`.
- `NOTICE` exists and records every source's commit, file and license.

A false or incomplete manifest refuses the whole pack. It never just leaves a file out.

## Organization lists

An organization adds its own words (branch codes, product names, local words) as lists of DNS
labels under Settings > Scanning > Wordlists, or with `/api/v1/wordlists`
([authorization-matrix.md](authorization-matrix.md)). No archive, manifest or git is needed: a list
is text, pasted or uploaded as a `.txt`.

- **Reading the text.** One entry per line; blank lines and lines starting with `#` are ignored, as
  is a trailing ` # comment`. An entry is lower-cased and kept when it is one to three dot-separated
  DNS labels (`[a-z0-9-]`, no leading or trailing `-`, at most 63 characters each) and not all
  digits. A line that looks like a secret (a label of 24 characters or more mixing letters and
  digits with high entropy) is refused, since every label is sent to resolvers. Repeats are removed,
  first occurrence first. The response reports what was kept and what was dropped, with examples.
- **Limits.** 20 lists per organization; 50,000 labels and 1 MiB per list; 2 MiB of text per
  request.
- **Versions.** Each list has a `version` that rises when its labels change (not when only its name,
  description or switch changes) and the sha256 of its labels.
- **Use.** Every enabled list joins every subdomain enumeration job of the organization, on its own
  sensors and on shared sensors alike: the lists are merged in creation order without repeats and
  carried inline under the job signature, after the learned labels and before the platform pack.
  The job's inline budget (256 KiB compressed per list) keeps the leading labels of a larger merge.
  Nothing is stored on a sensor beyond the task directory, which is erased with the task.
- **Preview.** `GET /api/v1/wordlists/preview?root=example.com&depth=standard` counts what a job of
  that root would carry: the platform pack (name, version, line count), the learned labels and
  permutations, and the organization's labels. It returns counts and list names only, and sends
  nothing to any sensor or resolver.
- **Audit.** `wordlist.created`, `wordlist.updated` and `wordlist.deleted`, with name, version and
  line count, never the labels.

## What a run used

When the platform signs a job for a sensor it stores what the job read on the command
(`commands.content_pins`): each pack with its slot, name, version and digest, and each inline list
with its source (`learned` or `organization`), line count and sha256, plus the organization lists
it holds with the version each had. The run page shows it per task. The record comes from what was
signed, never from the sensor, and a retry of the job rewrites it.

Isolation: organization lists and the learned labels are read with the job's own tenant id and
reach a sensor only inside that organization's signed job; the record is written under the same
tenant.

## Licenses

Allowed: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0, Unlicense, WTFPL, CC-BY-4.0.
Opt-in packs only, with attribution: CC-BY-SA-3.0 and CC-BY-SA-4.0. Refused: GPL, AGPL, no
license, unknown. Examples of what this leaves out: the RAFT directory and file lists (the RAFT
project is GPL-3.0), a subdomain list that is GPL-3.0 upstream although it sits in an MIT
repository, and lists with no license file. The current list is in `sources.yaml`.

## Threat model

- A poisoned upstream file: pinned commit and sha256, so a changed file fails the build; the diff
  of the lists is read before a release is published; entries that are URLs, wildcards or contain
  control characters are dropped and a linter check refuses them again on import.
- License breach: per-file allow-list, enforced before download, repeated by the linter on import.
- Tampering in transit or at rest: the import route checks the asset sha256 before parsing; the
  platform signs the pack; sensors verify digest and signature.
- Isolation: these are platform packs, public to every organization; nothing tenant-specific is in
  them. The learned list and its permutations are built from the job's organization's names only,
  travel inline under the job signature, and are never stored or cached.
- The built-in packs never override an administrator: they install only where no `stable` channel
  exists, and only when the ingested digest is the recorded one.
