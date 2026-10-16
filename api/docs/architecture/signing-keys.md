# Signing keys

Two things OpenCTEM publishes are signed so an instance can trust them
without trusting the host that serves them: the **release feed** (the
version check, [version-check.md](version-check.md)) and the **content
catalog** ([content-catalog.md](content-catalog.md)). Instances only verify;
every key below lives with the maintainers.

## What each key does

| Key | Where it lives | What it signs | What the instance pins |
|---|---|---|---|
| **Release feed key** | the GitHub secret `RELEASE_FEED_SIGNING_KEY` of the `release-feed` environment (restricted to `main` and `v*` tags); one encrypted backup | only the release feed | its public key, hex, in `releasefeed.PinnedKeys` (at most two entries) |
| **Catalog online key** | the GitHub secret `CONTENT_CATALOG_SIGNING_KEY` of the `content-catalog` environment (restricted to `main` and `v*` tags like `release-feed`); one encrypted backup | the content catalog's index, statements and revocations | its public key, through the catalog key set, in the catalog trust |
| **Catalog root key** | offline (encrypted stick or password manager attachment, two copies); never in CI | only the catalog **key set**: the list of catalog online keys the catalog accepts, valid at most 365 days | its key id in `contentpkg.PinnedRoots` |

The release feed has no key set and no root: it is display-only (bounded
fields, links under our own hosts, nothing downloaded or run because of it),
so one pinned online key is enough. The catalog can install content, so it
keeps the second tier: a stolen online key is revoked by signing a new key set
without it, and the root never touches CI.

The two online keys are different keys, kept in different GitHub
environments, and the catalog key set never lists the release feed key: a key
that signs information must not be able to ship code, and the reverse. A
signature also covers the DSSE payload type
(`application/vnd.openctem.release-feed+json` for the feed,
`...catalog-keyset+json`, `...package-index+json` and so on for the catalog),
so a signature made for one document type is never valid as another, even
under a key both would trust.

Key set validity is per feed: the content catalog's is at most 365 days; the
program feed's and the vulnerability bundle's are at most 180 days.

## First setup (once, by the owner, on the owner's own machine)

```bash
scripts/signing/init-keys.sh            # or: scripts/signing/init-keys.sh /path/to/keys
```

It creates the root key, the release feed key, the catalog online key and the signed key set (which lists the catalog online key only) in a directory
(default `./openctem-signing-keys`, mode 0700, keys 0600), refuses to
overwrite existing keys, and prints only public material: the key ids, the
two online public keys, the file to commit (`keyset.dsse.json`) and the exact
`gh secret set` commands (`RELEASE_FEED_SIGNING_KEY` in `release-feed`,
`CONTENT_CATALOG_SIGNING_KEY` in `content-catalog`), which read each key from
its file and never print it. Then:

1. Pin the release feed public key in `releasefeed.PinnedKeys` and the root key id
   in `contentpkg.PinnedRoots`, and commit the key set, in one reviewed pull
   request.
2. Create the `content-catalog` GitHub environment (restricted to `main`
   and `v*` tags, like `release-feed`) and run the printed `gh secret set`
   commands.
3. Move `catalog-root.key` offline (two copies) and remove it from the
   machine.

Until the keys are pinned, the version check and the catalog import are inert.

## Yearly task: re-sign the catalog key set

The catalog key set expires after 365 days. About a month before:

```bash
scripts/signing/rotate-keyset.sh /path/to/keys    # root key mounted for the moment
```

It signs a new key set with the next version and a new 365 days, keeps the old
one as `keyset.dsse.json.prev`, and prints the file to commit and publish. The
release feed needs nothing: its freshness is the weekly re-sign (feeds expire
after 45 days).

## Rotating an online key

The steps below are for the release feed key; the catalog online key rotates
through the key set alone (steps 3 and 4 with the `content-catalog` secret).

Without compromise, with an overlap so no instance is left behind:

1. Create a new key pair (`go run ./cmd/release-feed keygen -out new-online.key`
   in `api/`).
2. Ship a release that pins **both** public keys in `releasefeed.PinnedKeys`.
3. For the catalog online key: re-sign the catalog key set listing both
   catalog online keys (`ONLINE_PUBS=<old>,<new> scripts/signing/rotate-keyset.sh`).
4. After instances have upgraded, switch the `RELEASE_FEED_SIGNING_KEY` secret
   to the new key.
5. In a later release, drop the old key from `PinnedKeys`, and re-sign the key
   set with the new key only.

## If an online key is compromised

1. Rotate the secret to a new key at once (the old one still verifies on
   instances until step 3, which the feed's display-only limits make
   tolerable; no instance runs anything because of the feed).
2. Catalog: sign a new key set without the stolen key
   (`ONLINE_PUBS=<new> scripts/signing/rotate-keyset.sh`), publish it, and
   publish a revocation list for anything the stolen key signed. Instances
   refuse a key set below the version they applied, so the revoked key cannot
   come back.
3. Feed: ship a release that pins the new key and drops the stolen one.

## If the root key is lost or compromised

Lost: the current key set stays valid until it expires; make a new root with
`init-keys.sh` in a fresh directory, and ship a release pinning the new root
alongside the old one before the old key set expires. Compromised: ship a
release that pins only a new root, immediately; treat everything signed under
the old root after the compromise as untrusted and revoke it.
