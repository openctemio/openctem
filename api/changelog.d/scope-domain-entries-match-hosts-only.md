### Security: a domain scope entry authorizes host names only

- A domain entry such as `*.example.com` matched the raw text of a URL whose path, query or fragment ended in `.example.com` (for example `http://other.test/?q=.example.com`), so a target on any host passed the scope check, the claim-time recheck and the job signer. Domain entries now match host names only; a URL or host:port target is authorized through its host.
- A network counts as internal (no scope entry needed) only when all of it lies inside an internal block: `0.0.0.0/0`, `10.0.0.0/1` and `::/0` now need a scope entry.
- A host written as a decimal or hex number (`2852039166`, `0xa9fea9fe`) needs a scope entry, which no entry grants.
- An IP address entry matches the same address in any spelling (`2001:DB8::1`, `::ffff:10.0.0.5`).
