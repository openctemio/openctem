### Fixed: the API starts again without APP_URL

- With APP_URL unset (MCP OAuth discovery off) the API panicked at startup while wiring the get_asset tool. It now starts, and get_asset answers without console links.
