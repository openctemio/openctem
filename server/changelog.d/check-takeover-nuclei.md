### Added: the takeover check step runs nuclei's takeover templates

- `check.takeover` is now a routed capability: nuclei runs it with only its `takeover` templates, on domains and subdomains (active, T1). The takeover check step of Subdomains and Deep recon runs instead of being skipped; a match on a name whose DNS check holds an open dangling CNAME raises a confirmed subdomain takeover, as nuclei takeover findings already did.
- The step cannot widen the template set: the tag set is fixed by the platform at dispatch and checked again by the sensor. The job runs as a nuclei job, so every sensor version takes it (no sensor upgrade needed).
- A workflow step that pins nuclei without naming a capability still runs vulnerability templates.
