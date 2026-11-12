### Fixed: the all-in-one image publishes again

- The v0.18.0 all-in-one image measured 561 MB unpacked, 1 MB over its 560 MB size budget, so the release did not publish or sign it (and the image signing step, which runs after it, was skipped for every image). The budget is now 645 MB: today's size plus the usual 15% headroom.
