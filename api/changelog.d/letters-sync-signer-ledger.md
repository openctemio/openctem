### Security: letters and program sync keep the job signer ledger in step

- Revoking an authorization letter takes every scope entry that names it out of the job signer scope ledger. RFC-040 §11.5, RFC-065 §13.
- A letter entry is in the ledger only while its letter is valid, and its ledger expiry is never later than the letter end. The signer stops signing for it when the letter expires, without waiting for the next ledger sync.
- A program scope sync writes through the same hook:
  - removals and a closed program take entries out;
  - accepted new terms put entries in under the program attestation, and nothing is saved when the signer refuses.
