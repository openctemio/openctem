/**
 * A fitted flow view keeps every node clear of the canvas controls: the
 * zoom stack at the bottom left always, the full-screen button at the top
 * right when the canvas offers it.
 */
import { describe, it, expect } from 'vitest'
import { flowFitOptions } from '../flow-canvas'

const px = (v: string | number | undefined) => parseInt(String(v), 10)

describe('flowFitOptions', () => {
  it('reserves the zoom stack (12 px margin + 32 px buttons) on the left', () => {
    for (const full of [false, true]) {
      expect(px(flowFitOptions(full).padding.left)).toBeGreaterThanOrEqual(12 + 32 + 8)
    }
  })

  it('reserves the full-screen button row at the top only when it is shown', () => {
    expect(px(flowFitOptions(true).padding.top)).toBeGreaterThanOrEqual(12 + 32 + 8)
    expect(px(flowFitOptions(false).padding.top)).toBeLessThan(12 + 32)
  })

  it('never zooms past 1 to fill the view', () => {
    expect(flowFitOptions(false).maxZoom).toBe(1)
  })
})
