### Security: the web's production dependency tree no longer carries knip

- `knip` (an unused-code finder used only during development) moved from `dependencies` to `devDependencies` in the web app. `npm audit --omit=dev` drops from 4 high findings (ReDoS in `braces` through `fast-glob`/`micromatch`, pulled in only by knip) to none.
