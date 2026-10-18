import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// The six integration writes ask for step-up on the server. A call through
// csrfFetch (raw fetch) bypasses the global step-up dialog, so the user would
// see a bare 403 instead of the re-authentication prompt. Every such write must
// go through apiClient (post/put/del), which opens the dialog and retries once.
// Reads and the test/sync actions do not need step-up and may stay on csrfFetch.
const STEP_UP_WRITES: RegExp[] = [
  /\/api\/v1\/integrations\/\$\{[^}]+\}`,\s*\{[^}]*method:\s*'(DELETE|PUT)'/,
  /\/api\/v1\/integrations\/\$\{[^}]+\}\/notification`,\s*\{[^}]*method:\s*'PUT'/,
  /\/api\/v1\/integrations\/\$\{[^}]+\}\/disable`,\s*\{[^}]*method:\s*'POST'/,
  /'\/api\/v1\/integrations(\/notifications)?',\s*\{[^}]*method:\s*'POST'/,
]

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name !== '__tests__' && name !== 'node_modules') sources(p, out)
    } else if (/\.(ts|tsx)$/.test(name)) {
      out.push(p)
    }
  }
  return out
}

describe('integration writes that need step-up', () => {
  it('never use csrfFetch', () => {
    const offenders: string[] = []
    for (const file of sources(join(process.cwd(), 'src'))) {
      const text = readFileSync(file, 'utf8')
      if (!text.includes('csrfFetch(')) continue
      for (const re of STEP_UP_WRITES) {
        const calls = text.split('csrfFetch(').slice(1)
        if (calls.some((c) => re.test(c.slice(0, 300)))) offenders.push(`${file}: ${re}`)
      }
    }
    expect(offenders).toEqual([])
  })
})
