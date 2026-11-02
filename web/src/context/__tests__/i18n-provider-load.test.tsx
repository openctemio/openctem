/**
 * A cold page load renders I18nProvider before its catalog has arrived. When
 * the catalog arrives while React is rendering, React replays the component
 * that suspended in use(); a replay of one that also calls hooks afterwards
 * threw React error 467 ("Update hook called on initial render"), an uncaught
 * page error on about one cold load in a few. The catalog here arrives in the
 * next task after the first render attempt (a cached chunk), and the cache is
 * empty each round.
 */
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const catalog = vi.hoisted(() => ({
  loaded: null as Record<string, string> | null,
  promise: null as Promise<Record<string, string>> | null,
}))

vi.mock('@/lib/i18n', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/i18n')>()),
  loadedDictionary: () => catalog.loaded,
  loadDictionary: () => {
    catalog.promise ??= new Promise<Record<string, string>>((resolve) =>
      setTimeout(() => resolve({ 'x.y': 'Z' }), 0)
    ).then((dict) => {
      catalog.loaded = dict
      return dict
    })
    return catalog.promise
  },
}))

import { I18nProvider, useTranslation } from '@/context/i18n-provider'

function Label() {
  return <span data-testid="label">{useTranslation().t('x.y', 'fallback')}</span>
}

describe('I18nProvider loading its catalog', () => {
  it('renders after the catalog arrives, with no render error, on a cold load', async () => {
    const errors: unknown[] = []
    for (let round = 0; round < 10; round++) {
      catalog.loaded = null
      catalog.promise = null
      const host = document.createElement('div')
      const root = createRoot(host, {
        onUncaughtError: (e) => errors.push(e),
        onCaughtError: (e) => errors.push(e),
        onRecoverableError: (e) => errors.push(e),
      })
      await act(async () => {
        root.render(
          <I18nProvider locale="en">
            <Label />
          </I18nProvider>
        )
      })
      await vi.waitFor(() =>
        expect(host.querySelector('[data-testid="label"]')?.textContent).toBe('Z')
      )
      root.unmount()
    }
    expect(errors.map(String)).toEqual([])
  })
})
