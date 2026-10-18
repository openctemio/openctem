/**
 * The console marks the reads it makes on its own (the periodic refresh of an
 * open page) so the API does not count them as activity: an unattended tab
 * still reaches the 15-minute idle timeout.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ADMIN_BACKGROUND_HEADER,
  INTERACTION_WINDOW_MS,
  adminFetch,
  isBackgroundRead,
  noteAdminInteraction,
  setAdminCsrfToken,
} from '../client'

describe('background reads', () => {
  const fetchMock = vi.fn()
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    setAdminCsrfToken('csrf-123')
    fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }))
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
    noteAdminInteraction()
  })

  const sentHeaders = (i = 0) => fetchMock.mock.calls[i][1].headers as Record<string, string>

  it('a read right after the administrator used the page is not background', async () => {
    noteAdminInteraction()
    await adminFetch('/overview')
    expect(sentHeaders()[ADMIN_BACKGROUND_HEADER]).toBeUndefined()
  })

  it('a read after a minute without a key, click or touch is background', async () => {
    noteAdminInteraction(Date.now() - INTERACTION_WINDOW_MS - 1000)
    await adminFetch('/overview')
    expect(sentHeaders()[ADMIN_BACKGROUND_HEADER]).toBe('1')
  })

  it('a write never carries the marker', async () => {
    noteAdminInteraction(Date.now() - INTERACTION_WINDOW_MS - 1000)
    await adminFetch('/announcements', { method: 'POST', body: { message: 'x' } })
    expect(sentHeaders()[ADMIN_BACKGROUND_HEADER]).toBeUndefined()
  })

  it('a key press marks the administrator as present again', async () => {
    noteAdminInteraction(Date.now() - INTERACTION_WINDOW_MS - 1000)
    expect(isBackgroundRead()).toBe(true)
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }))
    expect(isBackgroundRead()).toBe(false)
  })

  it('every read from a hidden tab is background', () => {
    noteAdminInteraction()
    const spy = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    expect(isBackgroundRead()).toBe(true)
    spy.mockRestore()
  })
})
