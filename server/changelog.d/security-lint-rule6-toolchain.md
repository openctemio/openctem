### Fixed: security lint Rule 6 when sdk-go needs a newer Go

- Rule 6 downloads the ctis version sdk-go pins to compare deny lists. Once sdk-go required Go 1.27, the download failed under the CI's pinned Go 1.26 and every API CI run failed. The download now fetches the toolchain it needs; nothing is built with it.
