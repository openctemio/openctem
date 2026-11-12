### Fixed: `backup.sh restore` stops the job signer before replacing its volumes

- The Compose restore wiped and unpacked `signer-keys` and `signer-state` while the `signer` container kept running, so the signer could write its sequence state into a half-restored volume. The restore now stops the signer too when it runs, and starts it again with the rest of the stack. The restore still leaves `.env` alone (restore `env.tar.gz` by hand on a new host).
