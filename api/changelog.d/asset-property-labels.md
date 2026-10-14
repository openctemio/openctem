### Changed: clearer labels for HTTP facts and asset sub-types

- The property `server` (synonym `web_server`) is labelled "HTTP server header" (vi "Header Server (HTTP)"): it is the `Server` response header a web probe recorded, and "Server" alone read as the organisation that runs the machine. `title` is labelled "Page title". Registry change only (`api/configs/asset-types.yaml`); no stored data changes.
- The asset drawer's type line shows the sub-type in words ("Host · Workstation", not "Host · workstation").
