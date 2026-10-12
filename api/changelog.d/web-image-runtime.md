### Changed: the web image ships node only, and its files are read-only to the server

- The `openctem-web` runtime is Alpine plus the node binary: npm, npx, the C
  headers and the glibc shim are no longer in the image at all (before, npm
  was deleted in a later layer, so its bytes still shipped in the base layer).
  amd64: 83.9 MB compressed / 282 MB unpacked before, 76.8 MB / 253 MB after.
- The application files are owned by root, so the Next.js server (uid 1001)
  can no longer modify its own code; `.next/cache` stays its only writable
  directory (with `/tmp`), as the read-only Compose deployment already assumes.
- The image no longer has the node image's `docker-entrypoint.sh` entrypoint;
  the command is still `node server-with-ws.mjs`.
