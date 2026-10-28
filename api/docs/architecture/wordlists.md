# Wordlists: the first-party packs

Design: research/294 (decisions D1, D2 and O2). Pack store and delivery:
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

The lists are not committed. The workflow `.github/workflows/wordlists-release.yml` (manual, from
`main`) publishes them as assets of the release `wordlists-<release>` with a build provenance
attestation. `release.json` in the release carries the asset sha256 of each pack.

## Import

A super admin imports each asset as a platform pack of kind `wordlist` with
`POST /api/v1/admin/content-packs/import` (https URL of the asset and its sha256; TOTP step-up,
a reason and an audit row, as for any platform pack) and then moves `stable` to it. No
platform code is specific to wordlists.

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
  them.
