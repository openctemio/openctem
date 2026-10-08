/**
 * SWR keys are endpoint URLs and the organization is in the session cookie,
 * so an organization switch must leave nothing of the old organization in the
 * cache (research/81). clearSwrCache drops every entry, then refetches what is
 * mounted.
 */
import * as React from 'react'
import { act, render, screen, waitFor } from '@testing-library/react'
import useSWR, { SWRConfig, useSWRConfig } from 'swr'
import { describe, expect, it, vi } from 'vitest'

import { clearSwrCache } from '../swr-config'

describe('clearSwrCache', () => {
  it('drops every cached answer before refetching', async () => {
    const mutate = vi.fn().mockResolvedValue(undefined)
    await clearSwrCache(mutate)
    expect(mutate).toHaveBeenNthCalledWith(1, expect.any(Function), undefined, {
      revalidate: false,
    })
    expect(mutate).toHaveBeenNthCalledWith(2, expect.any(Function))
    const matcher = mutate.mock.calls[0][0] as (k: unknown) => boolean
    expect(matcher('/api/v1/assets')).toBe(true)
    expect(matcher(['anything', 1])).toBe(true)
  })

  it('a mounted reader never shows the previous organization after the switch', async () => {
    let org = 'A'
    const fetcher = vi.fn(async () => `stats of ${org}`)
    let api: ReturnType<typeof useSWRConfig> | null = null
    function Reader() {
      api = useSWRConfig()
      const { data } = useSWR('/api/v1/dashboard/stats', fetcher)
      return <span data-testid="v">{data ?? 'loading'}</span>
    }
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <Reader />
      </SWRConfig>
    )
    await waitFor(() => expect(screen.getByTestId('v')).toHaveTextContent('stats of A'))

    org = 'B'
    const seen: string[] = []
    const observer = new MutationObserver(() =>
      seen.push(screen.getByTestId('v').textContent ?? '')
    )
    observer.observe(document.body, { subtree: true, childList: true, characterData: true })
    await act(async () => {
      await clearSwrCache(api!.mutate as never)
    })
    await waitFor(() => expect(screen.getByTestId('v')).toHaveTextContent('stats of B'))
    observer.disconnect()
    expect(seen).not.toContain('stats of A')
  })
})
