// The message catalogs, one JSON file per namespace (the first segment of
// every key) and locale: en/<namespace>.json and vi/<namespace>.json. Keys
// keep their full dotted name inside the file, so `t('scans.list.title')`
// lives in en/scans.json. Separate files keep pull requests that add text
// to different features from touching the same file. A new namespace needs
// one import in en.ts and one in vi.ts; dictionaries.test.ts fails on a file
// that is not imported, a key in the wrong file, a key in two files, or en
// and vi key sets that differ.
//
// Each locale is its own module (en.ts, vi.ts) so a page downloads only the
// catalog of its language: src/lib/i18n.ts loads it with a dynamic import.
// This index holds both, for tests and build-time checks only; importing it
// from application code would put every locale back into every page.

export type Dictionary = Record<string, string>

export { en, enNamespaces } from './en'
export { vi, viNamespaces } from './vi'
