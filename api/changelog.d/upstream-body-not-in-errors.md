### Security: upstream error responses no longer reach errors, API answers or audit text

- Jira, DefectDojo, the GitHub, GitLab and Bitbucket clients, OAuth and SSO put
  the third-party response body into their errors, which can reach API answers,
  audit entries and the console. They now return the provider and HTTP status
  only; a bounded, sanitized snippet of the body is logged at debug level
  (RFC-049 F-2). security-lint Rule 9 keeps it that way.
