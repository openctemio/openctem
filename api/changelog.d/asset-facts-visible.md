### Fixed: every asset fact is visible, and structured properties read as tables

- The "+N" after a chip list (IP addresses, CNAMEs, open ports, technologies, labels) is now a button that opens the full list, with a "Copy all" button, on click, tap or keyboard. It used to be a hover-only tooltip, so the hidden values could not be reached on touch screens or inside the asset drawer.
- The asset drawer's facts list every value instead of "+N".
- Asset properties render by shape: DNS records, open ports and other record lists as compact tables (type, name, value, TTL; port, protocol, service, product, version), objects as labelled values, deeper values as pretty-printed JSON in a collapsible block with a copy button, timestamps as local dates with the relative time. They used to print as one long JSON line.
- The property list gets a search box when it holds more than eight values, and labels of keys outside the registry keep their acronyms ("DNS record count", not "Dns record count").
