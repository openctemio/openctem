import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

// ErrorState phrases its title into "Couldn't load {title}": a literal title
// ("activity") stays English on a Vietnamese page. Titles come from t().
const SRC = join(__dirname, '..', '..', '..', '..')

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sources(path)
    return /\.tsx$/.test(name) && !/\.(test|stories)\.tsx$/.test(name) ? [path] : []
  })
}

describe('ErrorState titles', () => {
  it('are never literal text', () => {
    const literal = sources(SRC).flatMap((file) =>
      [...readFileSync(file, 'utf8').matchAll(/<ErrorState\s+title=["'][^"']*["']/g)].map(
        (m) => `${relative(SRC, file)}: ${m[0]}`
      )
    )
    expect(literal).toEqual([])
  })
})
