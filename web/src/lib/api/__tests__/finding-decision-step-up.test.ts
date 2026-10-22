import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// Approving a finding decision, deleting a finding and a bulk move to a
// closing status ask for step-up on the server. A raw csrfFetch call bypasses
// the shared re-authentication dialog, so the user would see a bare 403. These
// writes must go through apiClient (post/del), which opens the dialog and
// retries once. Rejects and cancels need no step-up and may stay as they are.
const STEP_UP_WRITES: RegExp[] = [
  /\/api\/v1\/findings\/bulk\/status/,
  /\/api\/v1\/findings\/\$\{[^}]+\}`,\s*\{[^}]*method:\s*'DELETE'/,
  /\/api\/v1\/approvals\/(batches\/)?\$\{[^}]+\}\/approve/,
  /severity-requests\/[^`]*approve/,
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

describe('finding decisions that need step-up', () => {
  it('never use csrfFetch', () => {
    const offenders: string[] = []
    for (const file of sources(join(process.cwd(), 'src'))) {
      const text = readFileSync(file, 'utf8')
      const calls = text.split('csrfFetch(').slice(1)
      for (const re of STEP_UP_WRITES) {
        if (calls.some((c) => re.test(c.slice(0, 300)))) offenders.push(`${file}: ${re}`)
      }
    }
    expect(offenders).toEqual([])
  })
})
