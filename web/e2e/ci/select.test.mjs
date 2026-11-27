// node --test web/e2e/ci
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  checkTags,
  globToRegExp,
  listSpecs,
  loadMap,
  parseMap,
  plan,
  select,
  shard,
  specTags,
  timingsFromReport,
  specHelpers,
  withHelperCosts,
} from './select.mjs'

const map = parseMap(`
smoke: '@smoke'
tags:
  - '@a'
  - '@b'
  - '@budget'
all:
  - web/src/components/**
  - web/e2e/ci/**
  - '!**/*.test.tsx'
ignore:
  - '**/*.md'
  - '**/*.test.tsx'
areas:
  '@a':
    - web/src/features/a/**
    - server/internal/infra/http/handler/a_*
  '@b':
    - web/src/features/b/**
  '@budget':
    - web/src/features/*/hooks/**
`)
const specs = [
  { file: 'e2e/specs/01-smoke.spec.ts', tags: ['@a', '@smoke'] },
  { file: 'e2e/specs/02-a.spec.ts', tags: ['@a'] },
  { file: 'e2e/specs/03-b.spec.ts', tags: ['@b'] },
  { file: 'e2e/specs/04-budget.spec.ts', tags: ['@budget'] },
]
const files = (r) => r.files.map((f) => f.split('/').pop())

test('a feature path selects its tag and the smoke set', () => {
  const r = select(['web/src/features/b/x.tsx'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.equal(r.mode, 'selected')
  assert.deepEqual(files(r), ['01-smoke.spec.ts', '03-b.spec.ts'])
})

test('an API handler maps to the same tag as the web feature', () => {
  const r = select(['server/internal/infra/http/handler/a_handler.go'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.deepEqual(files(r), ['01-smoke.spec.ts', '02-a.spec.ts'])
})

test('two areas union', () => {
  const r = select(['web/src/features/a/x.ts', 'web/src/features/b/y.ts'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.deepEqual(files(r), ['01-smoke.spec.ts', '02-a.spec.ts', '03-b.spec.ts'])
})

test('shared code runs everything', () => {
  const r = select(['web/src/features/b/x.tsx', 'web/src/components/Button.tsx'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.equal(r.mode, 'all')
  assert.equal(r.files.length, specs.length)
})

test('an unmapped path runs everything', () => {
  const r = select(['web/src/features/unknown/x.ts'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.equal(r.mode, 'all')
  assert.match(r.reason, /unmapped/)
})

test('e2e infrastructure runs everything', () => {
  assert.equal(select(['web/e2e/ci/compose.yml'], map, specs).mode, 'all')
})

test('only ignored paths select nothing', () => {
  const r = select(['docs/x.md', 'web/src/components/Button.test.tsx'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.equal(r.mode, 'none')
  assert.deepEqual(r.files, [])
})

test('a negated glob in all lets a unit test fall through to ignore', () => {
  assert.equal(
    select(['web/src/components/a.test.tsx'], map, specs, {
      event: 'pull_request',
      impact: true,
    }).mode,
    'none'
  )
})

test('a changed spec runs itself with the smoke set', () => {
  const r = select(['web/e2e/specs/03-b.spec.ts'], map, specs, {
    event: 'pull_request',
    impact: true,
  })
  assert.equal(r.mode, 'selected')
  assert.deepEqual(files(r), ['01-smoke.spec.ts', '03-b.spec.ts'])
})

test('full, push, schedule and an empty diff run everything', () => {
  assert.equal(select(['web/src/features/b/x.ts'], map, specs, { full: true }).mode, 'all')
  assert.equal(select(['web/src/features/b/x.ts'], map, specs, { event: 'push' }).mode, 'all')
  assert.equal(select(['web/src/features/b/x.ts'], map, specs, { event: 'schedule' }).mode, 'all')
  assert.equal(select([], map, specs, { event: 'pull_request', impact: true }).mode, 'all')
  assert.equal(
    select(['web/src/features/b/x.ts'], map, specs, { event: 'merge_group' }).mode,
    'all'
  )
})

test('a pull request runs the smoke set and the specs it edits, nothing else', () => {
  const r = select(['web/src/features/b/x.tsx'], map, specs, { event: 'pull_request' })
  assert.equal(r.mode, 'smoke')
  assert.deepEqual(files(r), ['01-smoke.spec.ts'])
  const own = select(['web/e2e/specs/03-b.spec.ts'], map, specs, { event: 'pull_request' })
  assert.deepEqual(files(own), ['01-smoke.spec.ts', '03-b.spec.ts'])
  // Shared paths do not widen a pull request without `impact`.
  const shared = select(['web/src/components/Button.tsx'], map, specs, { event: 'pull_request' })
  assert.equal(shared.mode, 'smoke')
})

test('the merge queue runs the whole suite', () => {
  const r = plan(['web/src/features/b/x.tsx'], map, specs, {}, { event: 'merge_group' })
  assert.equal(r.mode, 'all')
  assert.equal(r.specs, specs.length)
})

test('the request budget job exists only when @budget is selected', () => {
  const without = plan(
    ['web/src/features/b/x.tsx'],
    map,
    specs,
    {},
    { event: 'pull_request', impact: true }
  )
  assert.equal(without.budget, false)
  assert.ok(without.matrix.include.every((j) => !j.files.includes('04-budget')))
  const withIt = plan(
    ['web/src/features/b/hooks/use-x.ts'],
    map,
    specs,
    {},
    { event: 'pull_request', impact: true }
  )
  assert.equal(withIt.budget, true)
  const job = withIt.matrix.include.find((j) => j.id === 0)
  assert.equal(job.files, 'e2e/specs/04-budget.spec.ts')
  assert.ok(
    withIt.matrix.include.filter((j) => j.id !== 0).every((j) => !j.files.includes('04-budget'))
  )
})

test('mode none gives an empty matrix', () => {
  const r = plan(['docs/x.md'], map, specs, {}, { event: 'pull_request', impact: true })
  assert.equal(r.count, 0)
  assert.deepEqual(r.matrix.include, [])
})

test('shards: count follows total duration, clamped to 1..7', () => {
  const fs = Array.from({ length: 10 }, (_, i) => `f${i}`)
  const t = (s) => Object.fromEntries(fs.map((f) => [f, s]))
  assert.equal(shard(fs, t(10)).length, 1) // 100 s
  assert.equal(shard(fs, t(120)).length, 2) // 1200 s / 600 s
  assert.equal(shard(fs, t(600)).length, 7) // clamped
  assert.equal(shard([], {}).length, 0)
})

test('shards: the full suite leaves a shard well inside its 25 minute job timeout', () => {
  // The recorded durations of the full suite (about 5300 s) plus a stack start
  // of a few minutes and a retry or two must not reach the timeout.
  // The shard job has 25 minutes, of which the stack start takes about 3: a
  // shard must hold well under 17 minutes of tests, not nearly all of them.
  const specs = Array.from({ length: 127 }, (_, i) => `s${i}`)
  const bins = shard(specs, Object.fromEntries(specs.map((f) => [f, 5300 / 127])))
  assert.equal(bins.length, 7)
  assert.ok(Math.max(...bins.map((b) => b.seconds)) <= 14 * 60)
})

test('shards: longest first keeps the heaviest shard near the mean', () => {
  const timings = { a: 300, b: 200, c: 100, d: 100, e: 100, f: 100 }
  const bins = shard(Object.keys(timings), timings, { targetSeconds: 450, maxShards: 4 })
  assert.equal(bins.length, 2)
  assert.deepEqual(bins.map((b) => b.seconds).sort(), [400, 500])
  assert.equal(bins.flatMap((b) => b.files).length, 6)
})

test('shards: a spec without a recorded duration costs the heaviest recorded one', () => {
  const bins = shard(['a', 'b', 'c', 'new'], { a: 100, b: 200, c: 300 }, { targetSeconds: 10_000 })
  assert.equal(bins[0].seconds, 100 + 200 + 300 + 300)
  assert.equal(shard(['x'], {}, { targetSeconds: 10_000 })[0].seconds, 60)
})

test('shards: unrecorded specs are spread, not packed into one shard', () => {
  // Four specs the history does not know, next to fast known ones: the old
  // median cost put them all on one shard.
  const known = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`k${i}`, 30]))
  known.big = 400
  const files = [...Object.keys(known), 'n1', 'n2', 'n3', 'n4']
  const bins = shard(files, known, { targetSeconds: 400, maxShards: 5 })
  const holding = bins.filter((b) => b.files.some((f) => f.startsWith('n')))
  assert.ok(holding.length >= 3, `new specs share ${holding.length} shard(s)`)
})

test('every spec lands in exactly one shard', () => {
  const r = plan(
    ['web/src/components/x.tsx'],
    map,
    specs,
    {},
    { event: 'pull_request', impact: true }
  )
  const run = r.matrix.include.flatMap((j) => j.files.split(' '))
  assert.deepEqual([...run].sort(), specs.map((s) => s.file).sort())
})

test('timings sum the last attempt of each test per file', () => {
  const report = {
    suites: [
      {
        suites: [
          {
            specs: [
              {
                file: 'specs/a.spec.ts',
                tests: [{ results: [{ duration: 1000 }, { duration: 2000 }] }],
              },
              { file: 'specs/a.spec.ts', tests: [{ results: [{ duration: 500 }] }] },
            ],
          },
        ],
      },
    ],
  }
  assert.deepEqual(timingsFromReport(report), { 'e2e/specs/a.spec.ts': 2.5 })
})

test('timings count a test a helper declares for the spec that ran it', () => {
  const report = {
    suites: [
      {
        file: 'specs/62-list.spec.ts',
        suites: [
          {
            specs: [
              { file: 'helpers/list-stability.ts', tests: [{ results: [{ duration: 4000 }] }] },
            ],
          },
        ],
      },
    ],
  }
  assert.deepEqual(timingsFromReport(report), { 'e2e/specs/62-list.spec.ts': 4 })
})

test('globs', () => {
  assert.ok(globToRegExp('web/src/**').test('web/src/a/b.ts'))
  assert.ok(globToRegExp('web/src/features/*/hooks/**').test('web/src/features/x/hooks/y/z.ts'))
  assert.ok(!globToRegExp('web/src/*.ts').test('web/src/a/b.ts'))
  assert.ok(globToRegExp('web/src/app/(dashboard)/**').test('web/src/app/(dashboard)/p/page.tsx'))
  assert.ok(globToRegExp('**/*.test.ts').test('web/src/a.test.ts'))
  assert.ok(globToRegExp('**/*.test.ts').test('a.test.ts'))
})

test('tags are read from the Playwright tag option, in any form', () => {
  assert.deepEqual(specTags(`test('x', { tag: ['@a', '@smoke'] }, async () => {})`), [
    '@a',
    '@smoke',
  ])
  assert.deepEqual(specTags(`test.describe('x', { tag: "@b" }, () => {})`), ['@b'])
  assert.deepEqual(specTags(`test('x @phone', async () => {})`), [])
})

test('gate: a spec with no area tag fails', () => {
  const p = checkTags(map, [{ file: 'e2e/specs/x.spec.ts', tags: ['@smoke'] }, ...specs])
  assert.ok(p.some((m) => m.includes('x.spec.ts: no area tag')))
})

test('gate: an unknown tag, an unused tag and a bad area fail', () => {
  const p = checkTags(map, [...specs, { file: 'e2e/specs/y.spec.ts', tags: ['@zzz', '@a'] }])
  assert.ok(p.some((m) => m.includes('@zzz is not listed')))
  const unused = checkTags(
    map,
    specs.filter((s) => !s.tags.includes('@b'))
  )
  assert.ok(unused.some((m) => m.includes('@b in impact-map.yml is used by no spec')))
  const bad = { ...map, areas: { ...map.areas, '@nope': ['x/**'] } }
  assert.ok(checkTags(bad, specs).some((m) => m.includes('@nope is not listed')))
})

test('gate: a test Playwright sees untagged fails', () => {
  const listed = new Map([['e2e/specs/02-a.spec.ts', { all: [], untagged: ['bare test'] }]])
  assert.ok(checkTags(map, specs, listed).some((m) => m.includes('"bare test" has no area tag')))
})

test('the committed map and specs are consistent', () => {
  const real = loadMap()
  assert.deepEqual(checkTags(real, listSpecs()), [])
  const all = (paths) => select(paths, real, listSpecs(), { event: 'pull_request', impact: true })
  assert.equal(all(['web/src/features/findings/components/x.tsx']).mode, 'selected')
  assert.equal(all(['web/src/components/ui/button.tsx']).mode, 'all')
  assert.equal(all(['server/migrations/000001_x.up.sql']).mode, 'all')
  assert.equal(all(['web/src/lib/i18n/dictionaries/vi/findings.json']).mode, 'none')
  assert.equal(all(['web/src/lib/i18n/dictionaries/en/common.json']).mode, 'all')
  const f = all(['web/src/features/findings/x.tsx'])
  assert.ok(f.files.some((x) => x.includes('08-finding-detail-header')))
  assert.ok(
    f.files.some((x) => x.includes('01-login-and-invitation')),
    'smoke runs'
  )
  assert.ok(!f.files.some((x) => x.includes('42-vulnerability-page')))
})

test('a pull request that changes a page data hook also runs the request budget check', () => {
  const r = select(['web/src/features/b/hooks/use-b.ts'], map, specs, { event: 'pull_request' })
  assert.equal(r.mode, 'smoke')
  assert.deepEqual(files(r), ['01-smoke.spec.ts', '04-budget.spec.ts'])
  const plain = select(['web/src/features/b/x.tsx'], map, specs, { event: 'pull_request' })
  assert.deepEqual(files(plain), ['01-smoke.spec.ts'])
})

test('a spec without a duration takes its part of a helper filed under the helper', () => {
  assert.deepEqual(
    specHelpers(`import { x } from '../helpers/list-stability'\nimport y from '../fixtures/a'`),
    ['e2e/specs/helpers/list-stability.ts']
  )
  const specs = [
    { file: 'e2e/specs/62.spec.ts', tags: [], helpers: ['e2e/specs/helpers/list-stability.ts'] },
    { file: 'e2e/specs/35.spec.ts', tags: [], helpers: ['e2e/specs/helpers/list-stability.ts'] },
    { file: 'e2e/specs/a.spec.ts', tags: [], helpers: [] },
  ]
  const t = withHelperCosts(
    { 'e2e/specs/helpers/list-stability.ts': 1200, 'e2e/specs/a.spec.ts': 10 },
    specs
  )
  assert.equal(t['e2e/specs/62.spec.ts'], 600)
  assert.equal(t['e2e/specs/35.spec.ts'], 600)
  // The two long specs go to different shards.
  const bins = shard(['e2e/specs/62.spec.ts', 'e2e/specs/35.spec.ts', 'e2e/specs/a.spec.ts'], t, {
    targetSeconds: 240,
    maxShards: 4,
  })
  assert.ok(
    bins.every(
      (b) => !(b.files.includes('e2e/specs/62.spec.ts') && b.files.includes('e2e/specs/35.spec.ts'))
    )
  )
})

test('estimates name only specs that exist', async () => {
  const { loadEstimates, listSpecs } = await import('./select.mjs')
  const files = new Set(listSpecs().map((s) => s.file))
  const est = loadEstimates()
  assert.ok(Object.keys(est).length > 0)
  for (const f of Object.keys(est)) assert.ok(files.has(f), `${f} is not a spec`)
})
