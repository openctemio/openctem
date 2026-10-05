/**
 * The command palette is not mounted (or downloaded) until it first opens.
 */
import { act, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

vi.mock('@/components/command-menu', () => ({
  CommandMenu: () => <div data-testid="command-menu" />,
}))

import { SearchProvider, useSearch } from '@/context/search-provider'

function Opener() {
  const { setOpen } = useSearch()
  return (
    <button type="button" onClick={() => setOpen(true)}>
      open
    </button>
  )
}

describe('SearchProvider', () => {
  it('mounts the command menu only after the first open', async () => {
    render(
      <SearchProvider>
        <Opener />
      </SearchProvider>
    )
    expect(screen.queryByTestId('command-menu')).toBeNull()

    await act(async () => {
      screen.getByRole('button', { name: 'open' }).click()
    })
    expect(await screen.findByTestId('command-menu')).toBeTruthy()
  })

  it('opens on Cmd/Ctrl+K as before', async () => {
    render(
      <SearchProvider>
        <div />
      </SearchProvider>
    )
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))
    })
    expect(await screen.findByTestId('command-menu')).toBeTruthy()
  })
})
