### Security: the Alpine-based images carry OpenSSL 3.5.9-r1

- The web, console, gateway, all-in-one, migrations and seed images upgrade `libssl3` and `libcrypto3` to 3.5.9-r1 when they are built, which fixes the medium CVEs the image scan reported against 3.5.9-r0 in the pinned Alpine digest.
- Docs: none (image build only, no behaviour change)
