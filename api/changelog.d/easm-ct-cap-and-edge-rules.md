### Fixed: certificate transparency promotes every name of a large domain

- A domain with more than 500 subdomain names in certificate transparency had the same alphabetical tail cut on every run before promotion, so those hosts never reached inventory. The cap now bounds the subdomain exposure list only; every name is promoted, at most 500 new names per run, and the run logs when the exposure list was capped.

### Security: review by rule never suggests a range rule for CDN edge addresses

- An address inside a published CDN edge range (for example Cloudflare's) whose network had not been recorded yet was grouped under a suggested /24 rule; accepting it would have put shared provider space in scope. Such addresses are now listed one by one as shared, like the address cards and review rows already do.
