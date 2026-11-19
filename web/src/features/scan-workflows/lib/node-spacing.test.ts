import { describe, expect, it } from 'vitest'
import { spreadOverlapping } from './node-spacing'

const card = (id: string, x: number, y: number, height = 300) => ({
  id,
  x,
  y,
  width: 240,
  height,
})

describe('spreadOverlapping', () => {
  it('stacks parallel step cards that were laid out for a short card', () => {
    // The system "Code / CI" template: four parallel steps 103 px apart, cards about 300 px tall.
    const moved = spreadOverlapping(
      [card('a', 150, 100), card('b', 150, 203), card('c', 150, 306), card('d', 150, 409)],
      24
    )
    expect(Object.fromEntries(moved)).toEqual({ b: 424, c: 748, d: 1072 })
  })

  it('leaves cards that do not overlap where they are', () => {
    expect(spreadOverlapping([card('a', 0, 0, 100), card('b', 0, 110, 100)]).size).toBe(0)
    // Side by side in two columns.
    expect(spreadOverlapping([card('a', 0, 0), card('b', 300, 0)]).size).toBe(0)
  })

  it('a push that lands on another card moves past it too', () => {
    const moved = spreadOverlapping(
      [card('a', 0, 0, 200), card('b', 0, 150, 100), card('c', 0, 250, 100)],
      10
    )
    expect(Object.fromEntries(moved)).toEqual({ b: 210, c: 320 })
  })
})
