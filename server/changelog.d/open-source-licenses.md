### Added: About > Open-source licenses

- The tenant app and the platform console list the open-source components of the build (API, web app, console) with their versions, license identifiers and license texts, searchable, from Help > About > Open-source licenses.
- The lists are generated when the images are built (`api/cmd/third-party-notices`, `web/scripts/third-party-notices.mjs`) and served read-only to signed-in users at `GET /api/v1/licenses` and `GET /api/v1/admin/licenses` (API) and by each web server; nothing is fetched at run time. A build without the files shows an empty list.
- The page is part of the core: no brand or white-label setting removes it.
