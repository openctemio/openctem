### Fixed: the release smoke test works on images without a shell

- `smoke-image.sh` read the binary's ELF header and the OpenAPI spec through a
  shell inside the image, so the distroless `admin-cli` image failed its smoke
  test and the release's `admin-cli` build job could not pass. It now copies
  the files out of a stopped container with `docker cp`.
