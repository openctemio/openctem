### Fixed: the all-in-one image is published again

- The publish workflow downloaded the all-in-one digests with the pattern `digests-openctem-*`, which also matched the `openctem-api`, `openctem-web` and `openctem-gateway` digests, so the multi-arch manifest named digests of other images and v0.9.0 and v0.9.1 published no `ghcr.io/openctemio/openctem` image. The all-in-one digests now use their own artifact prefix.
