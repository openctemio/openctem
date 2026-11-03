// Types of the `@extension/*` modules. The bundler resolves them (next.config.ts:
// the stub in src/extension-default by default, the overlay when EDITION=ee); these
// declarations give both the same contract, from ./types.ts.
declare module '@extension/web' {
  export const extension: import('./types').WebExtension
}
declare module '@extension/console' {
  export const extension: import('./types').ConsoleExtension
}
declare module '@extension/messages' {
  export const messages: import('./types').ExtensionMessages
}
