### Security: notification e-mails no longer autolink untrusted URLs; MCP error logs cleaned

- Notification e-mails (plain-text and HTML parts) defang URLs and `mailto:` in the untrusted text (titles, bodies, field values, card text such as AI summaries or scanned page titles), so a mail client does not turn them into links. The notification's own link and the card's action stay clickable.
- MCP tool, prompt, write-tool, scope and campaign failures are logged through the shared error sanitiser (CR/LF removed, URL credentials and query strings redacted, length bounded) instead of the raw error text.
- Docs: none (no behaviour a user configures changes; chat notifications already defang the same text)
