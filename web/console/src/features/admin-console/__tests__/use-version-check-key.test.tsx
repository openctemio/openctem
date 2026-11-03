/**
 * The version check is read through one SWR key. The console site redirects a
 * path with a trailing slash to the one without, so a slashed key produced two
 * reads of the same resource on every page.
 */
import { describe, expect, it, vi } from 'vitest'

const swr = vi.hoisted(() => vi.fn((_key: string) => ({ data: undefined })))
vi.mock('swr', () => ({ default: swr }))
const adminFetch = vi.hoisted(() => vi.fn())
vi.mock('@console/lib/admin-api/client', () => ({ adminFetch, adminFetcher: vi.fn() }))

const { useVersionCheck, setVersionCheckEnabled, importReleaseFeed } =
  await import('../api/use-version-check')

describe('useVersionCheck', () => {
  it('reads /version-check without a trailing slash', () => {
    useVersionCheck()
    expect(swr.mock.calls[0][0]).toBe('/version-check')
  })

  it('writes to sub-paths of the same resource', () => {
    setVersionCheckEnabled(true)
    importReleaseFeed({})
    expect(adminFetch.mock.calls.map((c) => c[0])).toEqual([
      '/version-check/enabled',
      '/version-check/import',
    ])
  })
})
