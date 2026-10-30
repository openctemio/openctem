#!/usr/bin/env node
// i18n-json.mjs: the format, check and git merge driver of the message
// catalogs (src/lib/i18n/dictionaries/{en,vi}/<namespace>.json).
//
// Every catalog is one flat JSON object of dotted keys to strings, keys
// sorted by UTF-16 code unit (Array.prototype.sort), written as
// JSON.stringify(obj, null, 2) plus a newline. Sorted keys spread new text
// over the file instead of piling it up at the end, so two pull requests
// adding text to one namespace rarely touch the same lines.
//
//   node scripts/i18n-json.mjs sort           rewrite every catalog sorted
//   node scripts/i18n-json.mjs sort --check   exit 1 and list unsorted catalogs
//   node scripts/i18n-json.mjs merge O A B P  git merge driver (see below)
//
// Merge driver. Two branches that add or change different keys of one catalog
// always merge, whatever lines git would see: the three versions are merged
// key by key (a key changed on one side only takes that side, a key changed
// the same way on both sides is kept once, a key deleted on one side and
// untouched on the other is deleted) and written back sorted. Only a key
// that both sides changed differently is a conflict: the file then carries
// git conflict markers around that key's two lines and the driver exits 1,
// so git reports the file as conflicted. A version that is not a flat JSON
// object of strings is left to git's own line merge (git merge-file).
//
// Enable it once per clone (a clone without it falls back to git's line
// merge, which is still correct, only conflicts more often):
//   git config merge.i18n-json.name "i18n catalogs, merged key by key"
//   git config merge.i18n-json.driver "node web/scripts/i18n-json.mjs merge %O %A %B %P"
// The repository's .gitattributes routes the catalogs to it. GitHub's own
// merges (pull request test merges, the merge queue) never run merge drivers;
// this helps every local `git merge origin/develop`.
//
// Only Node's standard library is used; the driver reads the three files git
// hands it and writes %A, nothing else.

import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const DICT_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../src/lib/i18n/dictionaries'
)
const LOCALES = ['en', 'vi']

/** The catalog text for an object: keys sorted, two-space indent, final newline. */
export function format(obj) {
  const sorted = {}
  for (const k of Object.keys(obj).sort()) sorted[k] = obj[k]
  return JSON.stringify(sorted, null, 2) + '\n'
}

/** Parses a catalog; null when it is not a flat object of strings. */
export function parse(text) {
  let obj
  try {
    obj = JSON.parse(text)
  } catch {
    return null
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return null
  for (const v of Object.values(obj)) if (typeof v !== 'string') return null
  return obj
}

/**
 * Three-way merge of catalogs, key by key. Returns { merged, conflicts }:
 * merged holds every key that merged (an absent key means deleted), conflicts
 * lists [key, ours, theirs] for keys both sides changed differently
 * (undefined = deleted on that side).
 */
export function merge3(base, ours, theirs) {
  const merged = {}
  const conflicts = []
  const keys = new Set([...Object.keys(base), ...Object.keys(ours), ...Object.keys(theirs)])
  const get = (o, k) => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined)
  for (const k of [...keys].sort()) {
    const o = get(base, k)
    const a = get(ours, k)
    const b = get(theirs, k)
    let v
    if (a === b) v = a
    else if (a === o) v = b
    else if (b === o) v = a
    else {
      conflicts.push([k, a, b])
      continue
    }
    if (v !== undefined) merged[k] = v
  }
  return { merged, conflicts }
}

/** The merged catalog with conflict markers around each conflicting key. */
export function renderWithConflicts(merged, conflicts, label) {
  const line = (k, v) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`
  const entries = Object.keys(merged).map((k) => ({ k, text: [line(k, merged[k])] }))
  for (const [k, a, b] of conflicts) {
    entries.push({
      k,
      text: [
        `<<<<<<< ours`,
        ...(a === undefined ? [] : [line(k, a)]),
        '=======',
        ...(b === undefined ? [] : [line(k, b)]),
        `>>>>>>> theirs (${label})`,
      ],
    })
  }
  entries.sort((x, y) => (x.k < y.k ? -1 : x.k > y.k ? 1 : 0))
  const out = ['{']
  entries.forEach((e, i) => {
    const comma = i < entries.length - 1 ? ',' : ''
    for (const t of e.text) out.push(t.startsWith('  ') ? t + comma : t)
  })
  out.push('}')
  return out.join('\n') + '\n'
}

function cmdMerge([basePath, oursPath, theirsPath, label = 'catalog']) {
  if (!basePath || !oursPath || !theirsPath) {
    console.error('usage: i18n-json.mjs merge %O %A %B %P')
    return 2
  }
  const read = (p) => fs.readFileSync(p, 'utf8')
  // An added-on-both-sides file has an empty base.
  const baseText = read(basePath)
  const base = baseText.trim() === '' ? {} : parse(baseText)
  const ours = parse(read(oursPath))
  const theirs = parse(read(theirsPath))
  if (base === null || ours === null || theirs === null) {
    // Not a catalog this driver understands: git's own line merge, in place.
    try {
      execFileSync(
        'git',
        ['merge-file', '-L', 'ours', '-L', 'base', '-L', 'theirs', oursPath, basePath, theirsPath],
        {
          stdio: 'inherit',
        }
      )
      return 0
    } catch (e) {
      return typeof e.status === 'number' && e.status > 0 ? 1 : 2
    }
  }
  const { merged, conflicts } = merge3(base, ours, theirs)
  if (conflicts.length === 0) {
    fs.writeFileSync(oursPath, format(merged))
    return 0
  }
  fs.writeFileSync(oursPath, renderWithConflicts(merged, conflicts, label))
  console.error(
    `i18n-json: ${label}: ${conflicts.length} key(s) changed differently on both sides: ${conflicts
      .map(([k]) => k)
      .join(', ')}`
  )
  return 1
}

function catalogs() {
  const out = []
  for (const loc of LOCALES) {
    const dir = path.join(DICT_DIR, loc)
    for (const f of fs.readdirSync(dir).sort()) if (f.endsWith('.json')) out.push(path.join(dir, f))
  }
  return out
}

function cmdSort(args) {
  const check = args.includes('--check')
  const off = []
  for (const p of catalogs()) {
    const text = fs.readFileSync(p, 'utf8')
    const obj = parse(text)
    if (obj === null) {
      console.error(`i18n-json: ${p}: not a flat JSON object of strings`)
      return 1
    }
    const want = format(obj)
    if (want === text) continue
    off.push(path.relative(process.cwd(), p))
    if (!check) fs.writeFileSync(p, want)
  }
  if (check && off.length) {
    console.error(
      `i18n-json: ${off.length} catalog(s) not sorted; run: node web/scripts/i18n-json.mjs sort\n  ${off.join('\n  ')}`
    )
    return 1
  }
  if (!check && off.length) console.log(`i18n-json: sorted ${off.length} catalog(s)`)
  return 0
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (isMain) {
  const [cmd, ...rest] = process.argv.slice(2)
  const code =
    cmd === 'merge'
      ? cmdMerge(rest)
      : cmd === 'sort'
        ? cmdSort(rest)
        : (console.error('usage: i18n-json.mjs sort [--check] | merge %O %A %B %P'), 2)
  process.exit(code)
}
