### Fixed: the console draws its own fonts when run with `next dev` or `next start`

- `npm run dev:console` and a `build:console` + `next start console` run (the console's e2e suite and local runs)
  answered 404 for the six self-hosted font files and drew every page in a fallback font. A new step before both
  scripts copies `web/public/fonts` to `web/console/public/fonts` (ignored by git); a console e2e spec checks that each
  font the shared stylesheet loads is served.
- The console image was not affected: its Dockerfile stage already copies the same files.
- Docs: web/console/e2e/README.md (the new spec)
