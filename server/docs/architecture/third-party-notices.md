# Third-party notices (About > Open-source licenses)

Every build lists the open-source components it ships, with their versions,
their license identifiers and their license texts, on **About > Open-source
licenses** in the tenant app and in the platform console. The list is made
when the image is built and read from the image at run time: nothing is
fetched over the network.

The page is part of the core and is always present. No brand pack, white-label
setting or extension can remove or replace it: it is not an override point,
not behind a brand, module or feature setting, and
`web/src/features/about/__tests__/about-licenses-always-present.test.tsx`
asserts the routes and the About entry exist in both apps under any brand.

## Where the lists come from

| Part | Generator | When | File in the image |
|---|---|---|---|
| API | `server/cmd/third-party-notices` | `server/Dockerfile` builder stage, `build-dist.sh` (server archive) | `/app/third-party-notices.json` (all-in-one: `/opt/openctem/api/`) |
| Web app | `web/scripts/third-party-notices.mjs` | `web/Dockerfile` `notices` stage, `build-dist.sh` (web archive) | `/app/third-party-notices.json` |
| Console | the same script and file as the web app | the same stage, `build-dist.sh` (console archive) | `/app/console/third-party-notices.json` |

- **API:** `go list -deps -json ./cmd/server` names every package linked into
  the server; the tool keeps the module of each (the replacement's version and
  files for a replaced module), reads the `LICENSE`/`LICENCE`/`COPYING` files
  and then the `NOTICE` files at the module's root in the module cache, and
  names the license from its text (Go modules carry no license metadata).
  The Go standard library is listed from `GOROOT/LICENSE` at the toolchain's
  version. The listing is for the target platform (`GOOS`/`GOARCH`).
- **Web and console:** every `package-lock.json` entry that is not dev-only and
  is installed (other platforms' optional binaries are not), with the license
  identifier from the lockfile or `package.json` and the license and NOTICE
  files from `node_modules`. The console is built from the same packages, so it
  serves the same list.

Both files have one shape (`server/pkg/notices.Document`):
`{"generated": true, "component": "api"|"web", "packages": [{"name", "version", "license", "text"}]}`.
A license the tool cannot name is `Unknown`; a package without a license file
has an empty `text` and is still listed.

The generated files are not committed (`.gitignore`). A development build has
none: the endpoints answer `generated: false` and an empty list, and the page
says the list is made when the release image is built.

## Endpoints

| Route | Served by | Who |
|---|---|---|
| `GET /api/v1/licenses` | API | any signed-in user (JWT/session chain, no `oct_` keys) |
| `GET /api/v1/admin/licenses` | API | any console administrator (`platform.console.read`) |
| `GET /api/licenses` | web app | a browser with a tenant session cookie |
| `GET /api/v1/admin/web-licenses` | console (a static route ahead of the admin API proxy) | a browser with a console session cookie |

Security:

- Read-only, and no tenant data: the same document for every caller.
- Signed-in only, like `/version`: the exact dependency versions are not handed
  to anonymous clients, which could otherwise match them against known
  vulnerabilities without signing in.
- The file path is fixed by the binary (`notices.DefaultPath`, relative to the
  working directory, and `third-party-notices.json` next to each web server);
  no part of a request chooses what is read. The file is read once, bounded
  to 32 MiB; a missing, oversized or malformed file gives an empty list (the
  API logs why), never an error response.
