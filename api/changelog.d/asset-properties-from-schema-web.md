### Changed: asset Properties rendered from the property schema

- The Properties section of an asset follows its type's property schema (RFC-042 §6.3.9). Labels are in the viewer's language (English or Vietnamese) and in schema order. Each address links to its IP asset in the inventory, and URLs open only when they are http(s). An older row's synonyms (`ip`, `resolved_ips`, ...) show once, under "IP addresses". Third-party and custom keys are listed under "Other".
- The property filter and its chips use the same labels. The host and network pages, the export, the external-surface facts and the scope preview read addresses through the one schema helper.
