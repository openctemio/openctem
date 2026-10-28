### Security: an on-demand AI run never files a risk-lowering request

- When a person starts an AI analysis on demand, the analyst leaves a false-positive verdict or a severity downgrade as a comment instead of filing the request, because that person could otherwise approve it as the second person. Scheduled and event-triggered runs still file the request for a person to decide. Raising severity is unchanged.
- Masking fails closed: when the organization's or the asset's name cannot be read, the run (and the masking preview) stops instead of sending text in which those names are not masked.
