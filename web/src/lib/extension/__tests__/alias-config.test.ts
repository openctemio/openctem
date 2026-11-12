import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

/**
 * `@extension/*` is resolved by three tools that each read their own config:
 * the bundlers (next.config.ts of both apps), vitest, and tsconfig `paths`,
 * which Playwright uses to load the console e2e helpers (they import the
 * console navigation, which imports `@extension/console`). A tool missing the
 * mapping fails with "Cannot find module '@extension/console'" (the console
 * e2e break of 2026-11-04). Each config must point the default at the stub.
 */
const webRoot = path.resolve(__dirname, '../../../..')

function paths(tsconfig: string): Record<string, string[]> {
  const file = path.join(webRoot, tsconfig)
  return JSON.parse(readFileSync(file, 'utf8')).compilerOptions.paths
}

describe('@extension/* in tsconfig paths', () => {
  it.each([
    ['tsconfig.json', '.'],
    ['console/tsconfig.json', 'console'],
  ])('%s maps to the default stub', (tsconfig, base) => {
    const target = paths(tsconfig)['@extension/*']?.[0]
    expect(target).toBeDefined()
    const dir = path.resolve(webRoot, base, target!.replace('/*', ''))
    expect(dir).toBe(path.join(webRoot, 'src', 'extension-default'))
    for (const m of ['web', 'console', 'messages']) {
      expect(existsSync(path.join(dir, `${m}.ts`))).toBe(true)
    }
  })
})
