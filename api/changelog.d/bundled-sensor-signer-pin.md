### Security: the bundled sensor pins the job signer's key from a volume the API cannot write

- The signer writes its public key (`signer.pub`) to the new `signer-pub` volume (`SIGNER_PUBLISH_DIR`) at every start. Only the signer writes it; the bundled sensor mounts it read-only and reads it through `SENSOR_JOB_SIGNING_KEYS_FILE`; the API never mounts it. A compromised API can no longer choose the signing key the default sensor trusts.
- Needs a sensor release that reads `*_FILE` settings (sdk-go); an older sensor ignores the variable and keeps its current behaviour. Production installs should pin the offline root instead.
- The API image carries the `/var/lib/openctem-signer-pub` directory the volume starts from: pull the new image before starting the signer.
