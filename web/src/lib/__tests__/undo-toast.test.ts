import { beforeEach, describe, expect, it, vi } from 'vitest'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

import { UNDO_TOAST_MS, undoToast } from '../undo-toast'

const t = (_key: string, fallback?: string) => fallback ?? _key

function clickUndo() {
  const opts = toast.success.mock.calls[0][1] as {
    duration: number
    action: { label: string; onClick: () => void }
  }
  opts.action.onClick()
  return opts
}

const flush = () => new Promise((r) => setTimeout(r, 0))

describe('undoToast', () => {
  beforeEach(() => {
    toast.success.mockReset()
    toast.error.mockReset()
  })

  it('stays at least 8 seconds and labels the action Undo', () => {
    undoToast({ message: 'Archived', undo: vi.fn(), t })
    const opts = toast.success.mock.calls[0][1]
    expect(UNDO_TOAST_MS).toBeGreaterThanOrEqual(8000)
    expect(opts.duration).toBe(UNDO_TOAST_MS)
    expect(opts.action.label).toBe('Undo')
  })

  it('runs the inverse command once, even on a double click', async () => {
    const undo = vi.fn().mockResolvedValue(undefined)
    const onUndone = vi.fn()
    undoToast({ message: 'Archived', undo, t, onUndone })
    const opts = clickUndo()
    opts.action.onClick()
    await flush()
    expect(undo).toHaveBeenCalledTimes(1)
    expect(onUndone).toHaveBeenCalledTimes(1)
    expect(toast.success).toHaveBeenLastCalledWith('Change undone')
  })

  it('shows the failure when the inverse command is refused', async () => {
    const undo = vi.fn().mockRejectedValue(new Error('boom'))
    const onUndone = vi.fn()
    undoToast({ message: 'Archived', undo, t, onUndone, failedMessage: 'Could not restore' })
    clickUndo()
    await flush()
    expect(toast.error).toHaveBeenCalledTimes(1)
    expect(onUndone).not.toHaveBeenCalled()
  })

  it('stays quiet after the undo when the command reports its own result', async () => {
    const undo = vi.fn().mockResolvedValue(undefined)
    undoToast({ message: 'Status changed', undo, t, undoneMessage: false })
    clickUndo()
    await flush()
    expect(toast.success).toHaveBeenCalledTimes(1)
  })
})
