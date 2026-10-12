### Changed: the gateway compresses read responses

- The bundled gateway now compresses GET/HEAD responses of text types with
  zstd or gzip, whichever the client accepts. API JSON shrinks 6-13 times: a
  100-row findings page drops from 179 KB to 27 KB, the dashboard overview from
  69 KB to 8 KB, and the SBOM export from 4.8 MB to 0.37 MB.
- Write responses and the sign-in, OAuth and sensor APIs are never compressed.
  Those responses can carry a freshly issued secret next to request-controlled
  text, which is what a compression side channel (BREACH) needs.
- Event streams are not compressed, so they are never held back in a buffer.
