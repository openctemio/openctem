import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

/**
 * Search-as-you-type guard. Typed search text reaches the API only through
 * `useSearchQuery` (or `useListParams().apiParams` / `.searchTerm`, which use
 * it): debounce, minimum length, IME composition, hidden tab and 429 backoff
 * in one place. This fails on
 *
 * - `useDebounce` applied to a search value (it has no minimum length, no IME
 *   handling and no 429 backoff), and
 * - state set from a text input's change handler and put into a request
 *   (`search: x`, `q: x`, `?search=${x}`) without passing through the hook,
 *   which sends one request per keystroke.
 */
const WEB = join(__dirname, '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')]

function walk(path: string, out: string[]) {
  let st
  try {
    st = statSync(path)
  } catch {
    return
  }
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name.startsWith('.') || name === 'generated') continue
      walk(join(path, name), out)
    }
  } else if (/\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path)) {
    out.push(path)
  }
}

const files: string[] = []
for (const root of ROOTS) walk(root, files)
const rel = (abs: string) => relative(WEB, abs).split(sep).join('/')

const SEARCHY = /search|query|\bq\b|term|keyword|filter|tag/i

/** Setters fed by a text input as the user types. */
const INPUT_SETTERS = [
  /onChange=\{\s*\(?\s*(\w+)\s*\)?\s*=>\s*\{?\s*(set\w+)\(\s*\1\.target\.value/g,
  /(?:onValueChange|onSearchChange|onInputChange)=\{\s*(set\w+)\s*\}/g,
  /\bon\w*Search\w*:\s*(set\w+)/g,
  /(?:onValueChange|onSearchChange|onInputChange)=\{\s*\(?\s*(\w+)\s*\)?\s*=>\s*\{?\s*(set\w+)\(\s*\1\s*\)/g,
]

function inputStates(src: string): string[] {
  const setters = new Set<string>()
  for (const re of INPUT_SETTERS) {
    for (const m of src.matchAll(re)) setters.add(m[m.length - 1])
  }
  const states: string[] = []
  // A search kept in the URL is typed state too, when the input writes it
  // directly (a page that writes the URL once typing settles is fine).
  const urlState = /const \[(\w+),\s*(\w+)\]\s*=\s*useUrlFilter\(\s*['"`](q|search)['"`]/g
  for (const m of src.matchAll(urlState)) {
    if (setters.has(m[2])) states.push(m[1])
  }
  for (const setter of setters) {
    const m = src.match(new RegExp(`const \\[(\\w+),\\s*${setter}\\]\\s*=\\s*useState`))
    // Only search-like state: a create form's name field is sent on submit.
    if (m && SEARCHY.test(m[1])) states.push(m[1])
  }
  return states
}

function reachesRequest(src: string, state: string): boolean {
  // state is an identifier (captured as a word), so it needs no escaping
  const s = state
  const inParams = new RegExp(
    `\\b(search|q|query|keyword|filter)\\s*:\\s*${s}\\b(?!\\s*[.?]\\s*(length|filter|map))`
  )
  const inUrl = new RegExp(`(search|q|query|keyword)=\\$\\{\\s*(encodeURIComponent\\()?${s}\\b`)
  // A data hook called with the state in its params ({ search, page }) or an
  // SWR key built from it.
  const inHookArgs = new RegExp(
    `\\b(?!use(State|Memo|Callback|Effect|Ref|SearchQuery|Form|Debounce)\\b)use[A-Z]\\w*\\(\\s*\\{[^}]*?[{,\\s]${s}\\s*[,}]`
  )
  const inSwrKey = new RegExp(`useSWR\\w*\\(\\s*(\\[[^\\]]*\\b${s}\\b|\`[^\`]*\\$\\{\\s*${s}\\b)`)
  return inParams.test(src) || inUrl.test(src) || inHookArgs.test(src) || inSwrKey.test(src)
}

/**
 * Inputs whose typed value reaches the request on purpose, with the reason.
 * Keep this short: an explicit submit (Enter / a button) is the usual reason.
 */
const REVIEWED: Record<string, string> = {
  'src/app/(auth)/select-tenant/page.tsx#searchQuery':
    'filters the loaded team list on the client; `query` is a message placeholder',
  'src/features/assets/components/asset-owners-tab.tsx#ownerSearch':
    'filters the loaded owners on the client; `query` is a message placeholder',
  'src/features/sensors/components/sensors-section.tsx#searchQuery':
    'filters the loaded sensor fleet on the client (filterSensors)',
}

describe('typed search reaches the API through useSearchQuery', () => {
  it('useDebounce is not used for search values', () => {
    const hits = files.flatMap((abs) =>
      readFileSync(abs, 'utf8')
        .split('\n')
        .map((line, i) =>
          /useDebounce\(/.test(line) && SEARCHY.test(line.replace(/useDebounce/, ''))
            ? `${rel(abs)}:${i + 1}: ${line.trim()}`
            : null
        )
        .filter((x): x is string => x !== null)
    )
    expect(hits).toEqual([])
  })

  it('raw input state is never put into a request', () => {
    const hits: string[] = []
    for (const abs of files) {
      const src = readFileSync(abs, 'utf8')
      const file = rel(abs)
      for (const state of inputStates(src)) {
        if (REVIEWED[`${file}#${state}`]) continue
        if (reachesRequest(src, state)) hits.push(`${file}: ${state}`)
      }
    }
    expect(hits).toEqual([])
  })

  it('the guard catches a per-keystroke search', () => {
    const bad = [
      "const [search, setSearch] = useState('')",
      'const { data } = useAssets({ search, page: 1 })',
      '<Input value={search} onChange={(e) => setSearch(e.target.value)} />',
      'useSWR(`/api/v1/users?search=${search}`)',
    ].join('\n')
    expect(inputStates(bad)).toEqual(['search'])
    expect(reachesRequest(bad.replace('{ search,', '{ search: search,'), 'search')).toBe(true)
    expect(reachesRequest(bad, 'search')).toBe(true)
    const good = `
      const [search, setSearch] = useState('')
      const { term } = useSearchQuery(search)
      const { data } = useAssets({ search: term })
      <Input value={search} onChange={(e) => setSearch(e.target.value)} />
    `
    expect(reachesRequest(good, 'search')).toBe(false)
  })
})
