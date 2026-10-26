### Changed: smaller admin-cli image
- The admin-cli image shrinks from 42 MB to 36 MB: the Sigstore publisher verifier moved to `pkg/contentpkg/sigstore`, so binaries that only read the content catalog no longer link the Sigstore client, and the image uses the timezone data and CA bundle already in its base.
