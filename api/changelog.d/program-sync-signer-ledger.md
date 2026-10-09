### Security: program scope sync keeps the job signer ledger in step

- A program scope sync writes through the job signer ledger hook (RFC-040 §11.5, RFC-065 §14): removals and a closed program take entries out, accepted new terms put entries in under the program attestation (nothing is saved when the signer refuses), and the program group follows (data scope).
