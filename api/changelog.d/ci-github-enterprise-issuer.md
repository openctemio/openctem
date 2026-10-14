### Added: CI trust for GitHub Enterprise Server and enterprise issuers

- A GitHub Actions trust configuration accepts three issuers:
  - github.com, `https://token.actions.githubusercontent.com` (the default);
  - an enterprise's customized issuer, `https://token.actions.githubusercontent.com/<enterprise slug>`;
  - a GitHub Enterprise Server, `https://<host>/_services/token`.
- Repositories and pipeline links of a server are named on its host (`github.example.com/acme/api`).
- An internal server needs `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`.
- The trust dialog has an optional "GitHub Enterprise issuer" field. The connect wizard stays for github.com.
