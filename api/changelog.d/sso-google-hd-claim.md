### Security: Google Workspace SSO checks the hosted-domain claim

- A Google Workspace sign-in is admitted only when the verified id_token `hd`
  claim is one of the provider's allowed domains, or, when the provider lists
  none, a domain the organization verified by DNS. A consumer Google account
  registered with a company address (no `hd`) is refused, for JIT newcomers and
  existing members alike. The `hd` authorize parameter was only an account
  chooser hint.
- **Upgrade note:** a Google Workspace provider with no `allowed_domains` now
  needs the Workspace primary domain verified for the organization
  (Console > Organizations > SSO domains), or its users are refused.
