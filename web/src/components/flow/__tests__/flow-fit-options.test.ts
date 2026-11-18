/**
 * A fitted flow view keeps every node clear of the canvas controls: the
 * zoom stack at the bottom left always, the full-screen button at the top
 * right when the canvas offers it.
 */
import { describe, it, expect } from 'vitest'
import { READABLE_ZOOM, flowFitOptions, readableViewport } from '../flow-canvas'

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

describe('readableViewport', () => {
  const box = { width: 880, height: 620 }

  it('keeps the ordinary centred fit when the graph fits at a readable zoom', () => {
    expect(readableViewport({ x: 0, y: 0, width: 700, height: 300 }, box, false)).toBeNull()
  })

  it('opens a wide graph at the readable zoom from its start, clear of the zoom stack', () => {
    // One path of five columns, 340 px apart: the fit would be about 0.5.
    const bounds = { x: -340, y: 0, width: 1540, height: 120 }
    const vp = readableViewport(bounds, box, false)!
    expect(vp.zoom).toBe(READABLE_ZOOM)
    // Node text: 14 px titles and 12 px lines stay at least 12.9 and 11 px.
    expect(14 * vp.zoom).toBeGreaterThanOrEqual(12.8)
    expect(12 * vp.zoom).toBeGreaterThanOrEqual(11)
    // The leftmost node starts right after the zoom stack's padding.
    expect(bounds.x * vp.zoom + vp.x).toBeCloseTo(px(flowFitOptions(false).padding.left))
    // Vertically centred in the frame.
    const top = bounds.y * vp.zoom + vp.y
    const bottom = top + bounds.height * vp.zoom
    expect(Math.abs(top - (box.height - bottom))).toBeLessThan(2)
  })
})
