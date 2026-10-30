### Security: the claim-time scope recheck reads targets from the run context

- A job that named its targets only in its run context (`context.targets`) had nothing to recheck and was handed out unchecked, although the narrowing already edited that context. The recheck now reads the context targets too, cuts a target refused since dispatch and fails a job with nothing left.

### Fixed: an exclusion that can never match is refused

- Creating an exclusion with a reversed range (`10.0.0.9-10.0.0.1`), an impossible network (`10.0.0.0/33`), a network in an IP address exclusion, or a URL in a domain exclusion is refused with a validation error. Such exclusions were accepted and shown as protecting their target while excluding nothing. Existing exclusions are not changed.
