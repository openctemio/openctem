# extension-default

What the `@extension/web`, `@extension/console` and `@extension/messages`
modules resolve to in the default build: empty registrations, so the build
adds nothing to the core (no page, no navigation row, no string, no prompt).
An extension build resolves the same modules to its own implementation of
the web extension API in `src/lib/extension/types.ts`; see
`api/docs/development/editions-overlay.md`.
