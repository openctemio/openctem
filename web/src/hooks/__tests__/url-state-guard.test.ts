import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

/**
 * URL state convention guard. A page that reads URL state through the
 * use-url-param hooks writes it through the same module (setter returned by
 * useUrlFilter*, replaceUrlSearch, pushUrlSearch). The store also notices
 * router writes now, but a router.replace/push to a query-only URL
 * (`?tab=x`, `${pathname}?...`, `/same/path?...`) next to a hook reader is the
 * pattern that made tabs need a second click, so it fails here.
 */
const ROOTS = [
  join(__dirname, '..', '..', '..', 'src'),
  join(__dirname, '..', '..', '..', 'console', 'src'),
]

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

// router.replace(`?x`), router.replace('?x'), router.replace(qs ? `?${qs}` : ...),
// router.push(`${window.location.pathname}?...`), router.replace(`${pathname}...`)
const QUERY_ONLY_ROUTER_WRITE =
  /router\.(replace|push)\(\s*(?:[^,)]*\?\s*)?[`'"]\?|router\.(replace|push)\(\s*`\$\{(?:window\.location\.)?pathname\}/

describe('URL state writers', () => {
  it('a hook reader never writes the query through router.replace/push', () => {
    const files: string[] = []
    ROOTS.forEach((r) => walk(r, files))
    const hits = files.flatMap((abs) => {
      const src = readFileSync(abs, 'utf8')
      if (!/hooks\/use-url-param['"]/.test(src)) return []
      return src
        .split('\n')
        .map((line, i) =>
          QUERY_ONLY_ROUTER_WRITE.test(line)
            ? `${relative(join(ROOTS[0], '..'), abs).split(sep).join('/')}:${i + 1}: ${line.trim()}`
            : null
        )
        .filter((x): x is string => x !== null)
    })
    expect(hits).toEqual([])
  })

  it('the pattern catches the original bug', () => {
    expect(
      QUERY_ONLY_ROUTER_WRITE.test('router.replace(qs ? `?${qs}` : window.location.pathname)')
    ).toBe(true)
    expect(QUERY_ONLY_ROUTER_WRITE.test('router.replace(newUrl)')).toBe(false)
    expect(QUERY_ONLY_ROUTER_WRITE.test("router.push('/findings')")).toBe(false)
  })
})
