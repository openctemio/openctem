### Security: web build tooling no longer pulls glob and minimatch versions with known advisories

- The web dependency tree resolved glob 13.0.6 and minimatch 10.2.4 (build and lint tooling only, not shipped to browsers). Both are now pinned to patched releases (glob 14.0.3, minimatch 11.0.3) because no parent package release carries the fix yet. `npm audit --omit=dev` reports no vulnerabilities.
