### Fixed: the MCP connection key no longer offers "Never" expiry

- Settings > AI access (MCP) offered a key that never expires; the API
  requires every `oct_` key to expire within 1 to 365 days and refused the
  request. The page now offers 30 days, 90 days (default) or 1 year, the same
  choices as the API keys page (one shared list).
