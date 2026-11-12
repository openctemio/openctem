import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import { startMockApi } from './mock-api'

/**
 * Starts the mock API the web server reads from (Playwright calls the returned
 * teardown) and starts the comparison table the job prints as its summary.
 */
export default async function globalSetup(): Promise<() => Promise<void>> {
  const dir = path.join(__dirname, '..', '..', 'test-results-design')
  mkdirSync(dir, { recursive: true })
  writeFileSync(
    path.join(dir, 'summary.md'),
    '### Design gate\n\n| Page | Variant | Differing pixels | Expected: result |\n|---|---|---|---|\n'
  )
  const { server } = await startMockApi(Number(process.env.DESIGN_MOCK_PORT ?? '3199'))
  return () => new Promise<void>((resolve) => server.close(() => resolve()))
}
