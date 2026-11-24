### Fixed: the Alpine-based images no longer carry OpenSSL twice

- The migrations, seed, gateway, web, console and all-in-one images upgrade OpenSSL (3.5.9-r1) in a separate build stage and copy the patched root filesystem into one layer. The previous `apk upgrade` layer kept the old OpenSSL in the base layer beside the new one, which grew every image and pushed the migrations image over its size budget, so no v0.24.0 images were published.
- Docs: none (image build change only; no setting, API or behaviour changes)
