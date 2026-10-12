### Security: through MCP, a campaign client sees published findings only

- The MCP pentest tools (`list_campaign_findings`, `get_pentest_finding`, `list_retests`, `campaign_report_stats`) checked campaign membership but not the member's role, so a client member could read draft and in-review findings, their retests and their counts through an AI client. They now apply the same rule as the console: a client sees published findings only. A role that cannot be resolved is treated as a client (fail closed).
