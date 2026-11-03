### Added: web extension API

- The web app and the console have a public, versioned extension API (`web/src/lib/extension`): an extension build can add sidebar rows, settings pages, console rows, catalog entries (never replacing a core string), content in named slots of core pages (`reports.sections`, `settings.scim.sections`) and replace a short allowlist of components (`auth.footer`). The default build resolves the `@extension/*` modules to an empty default and renders nothing extra.
- A default production web build refuses to run while an extension is mounted without `EDITION=ee`; an `EDITION=ee` build without one fails to resolve.
