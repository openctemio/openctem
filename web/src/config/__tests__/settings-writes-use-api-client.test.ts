/**
 * Settings writes go through the shared API client, which opens the step-up
 * dialog and retries when the API asks for a recent sign-in. csrfFetch skips
 * that and the caller saw a bare "HTTP 403" (research 273 D17). Test and
 * preview calls that never need step-up may still use csrfFetch.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(__dirname, '..', '..')
const FILES = ['features/access-control/components/role-detail-sheet.tsx']

describe('settings writes use the shared API client', () => {
  for (const f of FILES) {
    it(`${f} does not call csrfFetch`, () => {
      expect(readFileSync(join(SRC, f), 'utf8')).not.toMatch(/csrfFetch/)
    })
  }
})
