### Changed: the release feed key is pinned

- Builds now trust the release feed's online signing key, so an install checks for new versions and security advisories, the Software updates page can import a feed file, and sensor install snippets pick up the published image digests. Before, no key was pinned and every feed was refused.
- A test refuses a build with no pinned key, at most two keys (rotation overlap) and only well-formed Ed25519 public keys.
