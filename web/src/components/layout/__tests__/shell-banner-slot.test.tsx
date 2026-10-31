import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'

let pending = true
vi.mock('@/context/bootstrap-provider', () => ({ useBootstrapPending: () => pending }))
vi.mock('@/lib/cookies', () => ({ getCookie: () => 'tenant-a' }))

import { ShellBannerSlot } from '../shell-banner-slot'

const KEY_A = 'openctem.shellBannerHeight.tenant-a'
const slot = () => document.querySelector('[data-slot="shell-banners"]') as HTMLElement

describe('ShellBannerSlot', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    pending = true
  })

  it('holds the last height while the session bootstrap is pending', () => {
    window.sessionStorage.setItem(KEY_A, '86')
    render(<ShellBannerSlot>{null}</ShellBannerSlot>)
    expect(slot().style.minHeight).toBe('86px')
  })

  it('reserves nothing when no banner showed earlier in the session', () => {
    render(<ShellBannerSlot>{null}</ShellBannerSlot>)
    expect(slot().style.minHeight).toBe('')
  })

  it('reserves only for its own organization', () => {
    window.sessionStorage.setItem('openctem.shellBannerHeight.tenant-b', '86')
    render(<ShellBannerSlot>{null}</ShellBannerSlot>)
    expect(slot().style.minHeight).toBe('')
  })

  it('releases the space once the bootstrap answered and records the real height', () => {
    window.sessionStorage.setItem(KEY_A, '86')
    const { rerender } = render(<ShellBannerSlot>{null}</ShellBannerSlot>)
    pending = false
    rerender(<ShellBannerSlot>{null}</ShellBannerSlot>)
    expect(slot().style.minHeight).toBe('')
    // jsdom lays nothing out: an empty slot measures 0, so the entry goes.
    expect(window.sessionStorage.getItem(KEY_A)).toBeNull()
  })

  it('ignores a stored value that is not a sane height', () => {
    window.sessionStorage.setItem(KEY_A, '<img>')
    render(<ShellBannerSlot>{null}</ShellBannerSlot>)
    expect(slot().style.minHeight).toBe('')
  })
})
