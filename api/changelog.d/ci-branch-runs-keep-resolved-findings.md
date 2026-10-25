### Security: Branch runs no longer reopen resolved findings; retiring a CI source keeps secrets open
- A scan or CI run on a branch other than the repository's default branch records a branch occurrence but no longer reopens a finding that was resolved on the default branch. A default-branch run still reopens it.
- Retiring a CI pipeline closes its other sole-source findings as before, but leaves leaked-secret findings open until they are rotated.
