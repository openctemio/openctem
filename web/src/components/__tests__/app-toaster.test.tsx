import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render } from '@testing-library/react'
import { toast } from 'sonner'

import { AppToaster, TOAST_TOKENS } from '../app-toaster'

const theme = vi.hoisted(() => ({ resolved: 'light' as string | undefined }))
vi.mock('next-themes', () => ({ useTheme: () => ({ resolvedTheme: theme.resolved }) }))

const realMatchMedia = window.matchMedia
afterEach(() => {
  window.matchMedia = realMatchMedia
  theme.resolved = 'light'
})

function viewport(phone: boolean) {
  window.matchMedia = ((q: string) => ({
    matches: phone && q.includes('max-width: 639px'),
    media: q,
    addEventListener() {},
    removeEventListener() {},
  })) as unknown as typeof window.matchMedia
}

async function toaster() {
  render(<AppToaster />)
  act(() => {
    toast('Saved')
  })
  return new Promise<HTMLElement | null>((resolve) =>
    setTimeout(() => resolve(document.querySelector<HTMLElement>('[data-sonner-toaster]')), 0)
  )
}

async function toasterPosition() {
  const list = await toaster()
  return [list?.getAttribute('data-y-position'), list?.getAttribute('data-x-position')]
}

const themeOf = (list: HTMLElement | null) =>
  list?.getAttribute('data-sonner-theme') ?? list?.getAttribute('data-theme')

describe('AppToaster', () => {
  it('shows toasts at the top on phones, clear of a bottom sheet footer', async () => {
    viewport(true)
    expect(await toasterPosition()).toEqual(['top', 'center'])
  })

  it('keeps toasts bottom right on larger screens', async () => {
    viewport(false)
    expect(await toasterPosition()).toEqual(['bottom', 'right'])
  })

  it('follows the dark theme instead of the sonner light default', async () => {
    viewport(false)
    theme.resolved = 'dark'
    expect(themeOf(await toaster())).toBe('dark')
  })

  it('is light when the theme is not resolved yet', async () => {
    viewport(false)
    theme.resolved = undefined
    expect(themeOf(await toaster())).toBe('light')
  })

  it('draws toasts with the brand tokens, not the sonner palette', async () => {
    viewport(false)
    const list = await toaster()
    for (const [name, value] of Object.entries(TOAST_TOKENS)) {
      expect(list?.style.getPropertyValue(name), name).toBe(value)
    }
    expect(list?.style.getPropertyValue('--normal-bg')).toBe('var(--popover)')
    expect(list?.style.getPropertyValue('--error-text')).toBe('var(--tone-danger-fg)')
  })
})
