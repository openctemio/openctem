### Changed: label-boundary tests for the scope gate

- The domain matcher, the API scope gate, the exclusion filter used by the claim-time recheck and the job signer now share one table of boundary vectors: `example.com` never covers `notexample.com` or `example.com.evil.test`, an exclusion of `dev.example.com` never removes `devops.example.com`, and trailing dots, case, punycode, `host:port` and URL forms all resolve to the same answer. Another tenant's entry covers nothing at each gate.
