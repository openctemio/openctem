import { afterEach, describe, expect, it } from 'vitest'
import { act, render } from '@testing-library/react'
import { toast } from 'sonner'

import { AppToaster } from '../app-toaster'

const realMatchMedia = window.matchMedia
afterEach(() => {
  window.matchMedia = realMatchMedia
})

function viewport(phone: boolean) {
  window.matchMedia = ((q: string) => ({
    matches: phone && q.includes('max-width: 639px'),
    media: q,
    addEventListener() {},
    removeEventListener() {},
  })) as unknown as typeof window.matchMedia
}

async function toasterPosition() {
  render(<AppToaster />)
  act(() => {
    toast('Saved')
  })
  const list = await new Promise<HTMLElement | null>((resolve) =>
    setTimeout(() => resolve(document.querySelector<HTMLElement>('[data-sonner-toaster]')), 0)
  )
  return [list?.getAttribute('data-y-position'), list?.getAttribute('data-x-position')]
}

describe('AppToaster', () => {
  it('shows toasts at the top on phones, clear of a bottom sheet footer', async () => {
    viewport(true)
    expect(await toasterPosition()).toEqual(['top', 'center'])
  })

  it('keeps toasts bottom right on larger screens', async () => {
    viewport(false)
    expect(await toasterPosition()).toEqual(['bottom', 'right'])
  })
})
