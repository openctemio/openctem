#!/usr/bin/env node
// Test-impact selection for the Playwright suite (research/295).
//
//   node web/e2e/ci/select.mjs plan --changed <file|-> [--event E] [--full] [--impact]
//        [--timings f.json] [--target-seconds 240] [--max-shards 4]
//        prints the plan as JSON: which specs run and how they are sharded
//   node web/e2e/ci/select.mjs timings <report.json>
//        prints { "<spec file>": seconds } from a merged Playwright JSON report
//   node web/e2e/ci/select.mjs check
//        the tag gate: every spec has an area tag, tags and impact-map.yml agree
//
// No dependencies: it runs in the workflow's decide job before any npm install.
// Every doubt resolves toward running more: an unmapped path, a missing or bad
// map, a failed diff all give "all". Only `none` skips the suite, and only when
// every changed path is listed under `ignore`.
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
export const E2E_DIR = path.resolve(here, '..')
export const SPEC_DIR = path.join(E2E_DIR, 'specs')
export const MAP_FILE = path.join(E2E_DIR, 'impact-map.yml')
// Playwright treats file arguments as patterns relative to the web/ directory.
const SPEC_PREFIX = 'e2e/specs/'

// ---- impact-map.yml: the small subset of YAML it uses -----------------------

export function parseMap(text) {
  const out = { smoke: '@smoke', tags: [], all: [], ignore: [], areas: {} }
  let section = null
  let area = null
  const unquote = (v) => v.trim().replace(/^(['"])(.*)\1$/, '$2')
  for (const raw of text.split('\n')) {
    const line = raw.replace(/(^|\s)#.*$/, '')
    if (!line.trim()) continue
    const indent = line.length - line.trimStart().length
    const body = line.trim()
    if (indent === 0) {
      const m = body.match(/^([a-z_]+):\s*(.*)$/)
      if (!m) throw new Error(`impact-map.yml: cannot read "${body}"`)
      area = null
      if (m[2]) {
        if (m[1] !== 'smoke') throw new Error(`impact-map.yml: "${m[1]}" takes a list`)
        out.smoke = unquote(m[2])
        section = null
      } else {
        if (!(m[1] in out)) throw new Error(`impact-map.yml: unknown section "${m[1]}"`)
        section = m[1]
      }
    } else if (section === 'areas' && indent === 2 && body.endsWith(':')) {
      area = unquote(body.slice(0, -1))
      if (out.areas[area]) throw new Error(`impact-map.yml: area ${area} listed twice`)
      out.areas[area] = []
    } else if (body.startsWith('- ')) {
      const item = unquote(body.slice(2))
      if (section === 'areas') {
        if (!area) throw new Error(`impact-map.yml: "${item}" outside an area`)
        out.areas[area].push(item)
      } else if (Array.isArray(out[section])) out[section].push(item)
      else throw new Error(`impact-map.yml: "${item}" outside a list`)
    } else {
      throw new Error(`impact-map.yml: cannot read "${body}"`)
    }
  }
  return out
}

export function loadMap(file = MAP_FILE) {
  return parseMap(readFileSync(file, 'utf8'))
}

// ---- globs ------------------------------------------------------------------

const globCache = new Map()
export function globToRegExp(glob) {
  let re = globCache.get(glob)
  if (re) return re
  let s = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++
        if (glob[i + 1] === '/') {
          i++
          s += '(?:.*/)?'
        } else s += '.*'
      } else s += '[^/]*'
    } else if (c === '?') s += '[^/]'
    else s += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  re = new RegExp(`^${s}$`)
  globCache.set(glob, re)
  return re
}

export const matches = (globs, file) => globs.some((g) => globToRegExp(g).test(file))

function matchesAll(globs, file) {
  const positive = globs.filter((g) => !g.startsWith('!'))
  const negative = globs.filter((g) => g.startsWith('!')).map((g) => g.slice(1))
  return matches(positive, file) && !matches(negative, file)
}

// ---- specs and their tags ---------------------------------------------------

// Tags a spec file declares with Playwright's `{ tag: [...] }` option.
export function specTags(source) {
  const tags = new Set()
  for (const m of source.matchAll(/\btag\s*:\s*(\[[^\]]*\]|'[^']*'|"[^"]*")/g)) {
    for (const t of m[1].matchAll(/@[A-Za-z0-9_-]+/g)) tags.add(t[0])
  }
  return [...tags].sort()
}

export function listSpecs(dir = SPEC_DIR) {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.spec.ts'))
    .sort()
    .map((f) => ({
      file: `${SPEC_PREFIX}${f}`,
      tags: specTags(readFileSync(path.join(dir, f), 'utf8')),
    }))
}

const matchesAny = (globs, changed) => !!globs && changed.some((f) => matches(globs, f))

// ---- selection --------------------------------------------------------------

// Tiers (api/docs/development/ci-cd.md, "E2E tiers"):
//   merge_group, push, schedule, dispatch, `full`  the whole suite
//   pull_request                                   the smoke set (and any spec the
//                                                  change edits, and the request
//                                                  budget check when the change
//                                                  touches a page's data), unless `impact`
//                                                  (the run-e2e label or a changed
//                                                  suite) asks for the specs the
//                                                  changed files map to
// -> { mode: 'all' | 'selected' | 'smoke' | 'none', reason, tags: [], files: [path...] }
export function select(changed, map, specs, { event = '', full = false, impact = false } = {}) {
  const all = (reason) => ({ mode: 'all', reason, tags: [], files: specs.map((s) => s.file) })
  if (full) return all('full tier requested')
  if (event !== 'pull_request') return all(`${event || 'this event'} runs everything`)
  if (!changed.length) return all('no changed files could be read')
  if (!impact) {
    const own = new Set(
      changed
        .map((f) => f.match(/^web\/(e2e\/specs\/[^/]+\.spec\.ts)$/)?.[1])
        .filter((f) => f && specs.some((s) => s.file === f))
    )
    // A change to how a page loads its data also runs the request budget check
    // (about 5 minutes): the queue would otherwise be the first to see a page
    // over its budget.
    const budgetTag = '@budget'
    const budget = matchesAny(map.areas[budgetTag], changed)
    return {
      mode: 'smoke',
      reason: `pull request: smoke set${own.size ? ` and ${own.size} changed spec(s)` : ''}${budget ? ' and the request budget check' : ''}`,
      tags: budget ? [budgetTag] : [],
      files: specs
        .filter(
          (s) =>
            own.has(s.file) || s.tags.includes(map.smoke) || (budget && s.tags.includes(budgetTag))
        )
        .map((s) => s.file),
    }
  }
  const tags = new Set()
  const direct = new Set()
  let ignored = 0
  for (const f of changed) {
    if (matchesAll(map.all, f)) return all(`shared or infrastructure path: ${f}`)
    const own = f.match(/^web\/e2e\/specs\/[^/]+\.spec\.ts$/)
    if (own) {
      const spec = specs.find((s) => `web/${s.file}` === f)
      if (spec) direct.add(spec.file)
      // A deleted spec has nothing left to run.
      ignored++
      continue
    }
    const hit = Object.entries(map.areas).filter(([, globs]) => matches(globs, f))
    if (hit.length) {
      for (const [tag] of hit) tags.add(tag)
    } else if (matches(map.ignore, f)) ignored++
    else return all(`unmapped path: ${f}`)
  }
  if (!tags.size && !direct.size && ignored === changed.length) {
    return { mode: 'none', reason: 'only paths that cannot change a page', tags: [], files: [] }
  }
  const files = specs
    .filter(
      (s) => direct.has(s.file) || s.tags.includes(map.smoke) || s.tags.some((t) => tags.has(t))
    )
    .map((s) => s.file)
  return {
    mode: 'selected',
    reason: `areas: ${[...tags].sort().join(' ') || 'none'}; ${direct.size} changed spec(s); smoke set`,
    tags: [...tags].sort(),
    files,
  }
}

// ---- shards -----------------------------------------------------------------

const median = (xs) => {
  if (!xs.length) return 0
  const s = [...xs].sort((a, b) => a - b)
  const m = s.length >> 1
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}

// Greedy longest-first: each spec goes to the lightest shard so far.
export function shard(
  files,
  timings,
  { targetSeconds = 240, maxShards = 4, fallbackSeconds = 60 } = {}
) {
  const known = files.map((f) => timings[f]).filter((v) => Number.isFinite(v) && v > 0)
  const dflt = median(known) || fallbackSeconds
  const cost = (f) => (Number.isFinite(timings[f]) && timings[f] > 0 ? timings[f] : dflt)
  const total = files.reduce((n, f) => n + cost(f), 0)
  const count = files.length
    ? Math.min(maxShards, Math.max(1, Math.ceil(total / targetSeconds)))
    : 0
  const bins = Array.from({ length: count }, () => ({ load: 0, files: [] }))
  for (const f of [...files].sort((a, b) => cost(b) - cost(a) || a.localeCompare(b))) {
    const bin = bins.reduce((a, b) => (b.load < a.load ? b : a))
    bin.files.push(f)
    bin.load += cost(f)
  }
  return bins.map((b) => ({ files: b.files.sort(), seconds: Math.round(b.load) }))
}

// The matrix the workflow reads with fromJSON. `budget` specs get a job of
// their own (the request budget check) and only when @budget is selected.
export function plan(changed, map, specs, timings, opts = {}) {
  const sel = select(changed, map, specs, opts)
  const isBudget = (f) => specs.find((s) => s.file === f)?.tags.includes('@budget')
  const budgetFiles = sel.files.filter(isBudget)
  const main = sel.files.filter((f) => !isBudget(f))
  const bins = shard(main, timings, opts)
  const include = bins.map((b, i) => ({
    id: i + 1,
    name: `shard ${i + 1}/${bins.length}`,
    files: b.files.join(' '),
    seconds: b.seconds,
  }))
  if (budgetFiles.length)
    include.push({ id: 0, name: 'request budget', files: budgetFiles.join(' '), seconds: 0 })
  return {
    mode: sel.mode,
    reason: sel.reason,
    tags: sel.tags,
    specs: sel.files.length,
    shards: bins.length,
    budget: budgetFiles.length > 0,
    count: include.length,
    matrix: { include },
  }
}

// ---- timings from a Playwright JSON report ----------------------------------

export function timingsFromReport(report) {
  const out = {}
  const walk = (suite) => {
    for (const sp of suite.specs ?? []) {
      const file = `${SPEC_PREFIX}${String(sp.file).replace(/^specs\//, '')}`
      for (const t of sp.tests ?? []) {
        const last = (t.results ?? []).at(-1)
        if (last && Number.isFinite(last.duration))
          out[file] = (out[file] ?? 0) + last.duration / 1000
      }
    }
    for (const s of suite.suites ?? []) walk(s)
  }
  for (const s of report.suites ?? []) walk(s)
  for (const k of Object.keys(out)) out[k] = Math.round(out[k] * 10) / 10
  return out
}

// ---- the tag gate -----------------------------------------------------------

// Pure part: problems found given the map, the statically read specs and the
// tags Playwright itself lists per file (null to skip that comparison).
export function checkTags(map, specs, listed = null) {
  const problems = []
  const valid = new Set(map.tags)
  const used = new Set()
  for (const s of specs) {
    const areas = s.tags.filter((t) => valid.has(t))
    if (!areas.length) problems.push(`${s.file}: no area tag (one of ${map.tags.join(' ')})`)
    for (const t of s.tags) {
      used.add(t)
      if (!valid.has(t) && t !== map.smoke && t !== '@serial' && t !== '@phone') {
        problems.push(`${s.file}: tag ${t} is not listed under tags in impact-map.yml`)
      }
    }
    if (listed) {
      const real = listed.get(s.file) ?? { all: [], untagged: [] }
      for (const title of real.untagged) problems.push(`${s.file}: test "${title}" has no area tag`)
      const missing = real.all.filter((t) => valid.has(t) && !s.tags.includes(t))
      if (missing.length)
        problems.push(`${s.file}: tags ${missing.join(' ')} are not written as { tag: [...] }`)
    }
  }
  for (const t of map.tags)
    if (!used.has(t)) problems.push(`tag ${t} in impact-map.yml is used by no spec`)
  for (const t of Object.keys(map.areas))
    if (!valid.has(t)) problems.push(`areas: ${t} is not listed under tags`)
  if (!used.has(map.smoke)) problems.push(`no spec carries ${map.smoke}`)
  return problems
}

// Playwright's own view: tests per file with their tags (needs `npm ci`).
function listFromPlaywright() {
  const webDir = path.resolve(E2E_DIR, '..')
  const json = execFileSync('npx', ['playwright', 'test', '--list', '--reporter=json'], {
    cwd: webDir,
    encoding: 'utf8',
    maxBuffer: 64 << 20,
    env: { ...process.env, E2E_BASE_URL: process.env.E2E_BASE_URL ?? 'http://localhost:3000' },
  })
  const files = new Map()
  const walk = (suite) => {
    for (const sp of suite.specs ?? []) {
      const key = `${SPEC_PREFIX}${String(sp.file).replace(/^specs\//, '')}`
      const entry = files.get(key) ?? { all: [], untagged: [] }
      const tags = (sp.tags ?? []).map((t) => (t.startsWith('@') ? t : `@${t}`))
      entry.all.push(...tags)
      files.set(key, entry)
      sp.__tags = tags
    }
    for (const s of suite.suites ?? []) walk(s)
  }
  const report = JSON.parse(json)
  for (const s of report.suites ?? []) walk(s)
  return { files, report }
}

function checkWithPlaywright(map, specs) {
  const { files, report } = listFromPlaywright()
  const valid = new Set(map.tags)
  const visit = (suite) => {
    for (const sp of suite.specs ?? []) {
      const key = `${SPEC_PREFIX}${String(sp.file).replace(/^specs\//, '')}`
      const tags = sp.__tags ?? []
      if (!tags.some((t) => valid.has(t))) files.get(key).untagged.push(sp.title)
    }
    for (const s of suite.suites ?? []) visit(s)
  }
  for (const s of report.suites ?? []) visit(s)
  return checkTags(map, specs, files)
}

// ---- command line -----------------------------------------------------------

function arg(argv, name, dflt) {
  const i = argv.indexOf(name)
  return i >= 0 ? argv[i + 1] : dflt
}

function readChanged(src) {
  const text = src === '-' ? readFileSync(0, 'utf8') : readFileSync(src, 'utf8')
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

function main(argv) {
  const [cmd] = argv
  if (cmd === 'plan') {
    const event = arg(argv, '--event', '')
    const full = argv.includes('--full')
    const impact = argv.includes('--impact')
    let timings = {}
    const tf = arg(argv, '--timings')
    if (tf) {
      try {
        timings = JSON.parse(readFileSync(tf, 'utf8'))
      } catch {
        console.error('select: no usable timings, using the default duration')
      }
    }
    const specs = listSpecs()
    let result
    try {
      const changed = readChanged(arg(argv, '--changed', '-'))
      result = plan(changed, loadMap(), specs, timings, {
        event,
        full,
        impact,
        targetSeconds: Number(arg(argv, '--target-seconds', 240)),
        maxShards: Number(arg(argv, '--max-shards', 4)),
      })
    } catch (e) {
      console.error(`select: ${e.message}; running everything`)
      result = plan(
        [],
        { smoke: '@smoke', tags: [], all: [], ignore: [], areas: {} },
        specs,
        timings,
        {
          event,
          full: true,
        }
      )
      result.reason = `selector error: ${e.message}`
    }
    process.stdout.write(`${JSON.stringify(result)}\n`)
    return 0
  }
  if (cmd === 'timings') {
    process.stdout.write(
      `${JSON.stringify(timingsFromReport(JSON.parse(readFileSync(argv[1], 'utf8'))), null, 1)}\n`
    )
    return 0
  }
  if (cmd === 'check') {
    const map = loadMap()
    const specs = listSpecs()
    const problems = argv.includes('--static')
      ? checkTags(map, specs)
      : checkWithPlaywright(map, specs)
    // The workflow passes spec paths to a shell word-split; keep them plain.
    for (const s of specs) {
      if (!/^[A-Za-z0-9._/-]+$/.test(s.file))
        problems.push(`${s.file}: spec file names use only letters, digits, . _ - /`)
    }
    if (problems.length) {
      for (const p of problems) console.error(`::error::${p}`)
      console.error(
        `e2e tags: ${problems.length} problem(s). Tag every test with { tag: ['@area'] }; see web/e2e/README.md`
      )
      return 1
    }
    console.log(`e2e tags: ${specs.length} specs, ${map.tags.length} tags, all consistent`)
    return 0
  }
  console.error('usage: select.mjs plan|timings|check')
  return 2
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)))
}
