### Fixed: Awaiting verification count and its view now list the same findings
- The verification queue on the Findings page left out claimed fixes that have no CVE (rule-only SAST, secret, misconfiguration and DAST findings), so a count of 1 opened an empty view. The queue now lists them in a "Without a CVE" section, each with its own Approve and Reject.
- The count and the view use one scope (the page's context filters) and both leave out pentest findings, which are verified in their own module.
- The findings list, stats and groups accept `cve_id_null=true` for findings with no CVE.
