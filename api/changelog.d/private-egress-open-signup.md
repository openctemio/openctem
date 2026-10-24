### Security: private egress ranges cannot be opened on an instance with open sign-up

- `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` opens the named private ranges to every organization's integrations. With `SIGNUP_MODE=open` anyone can create an organization, so the API now refuses to start when both are set.
- **Upgrade note:** an instance that sets both must unset the ranges, or use `SIGNUP_MODE=disabled` or `domain`.
