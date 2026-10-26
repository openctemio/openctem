import { describe, expect, it } from 'vitest'
import { flowNeighbour } from '../flow-keyboard'

// entry (0,0) → jump (1,-1) → db (2,0); entry → ci (1,1) → db
const nodes = [
  { id: 'entry', x: 0, y: 0 },
  { id: 'jump', x: 280, y: -150 },
  { id: 'ci', x: 280, y: 150 },
  { id: 'db', x: 560, y: 0 },
]
const edges = [
  { source: 'entry', target: 'jump' },
  { source: 'entry', target: 'ci' },
  { source: 'jump', target: 'db' },
  { source: 'ci', target: 'db' },
]

describe('flowNeighbour', () => {
  it('follows outgoing edges to the right and incoming edges to the left', () => {
    expect(flowNeighbour('jump', 'ArrowRight', nodes, edges)).toBe('db')
    expect(flowNeighbour('db', 'ArrowLeft', nodes, edges)).toBe('jump')
    expect(flowNeighbour('ci', 'ArrowLeft', nodes, edges)).toBe('entry')
  })

  it('picks the neighbour nearest in height, then reading order', () => {
    expect(flowNeighbour('entry', 'ArrowRight', nodes, edges)).toBe('jump')
  })

  it('moves up and down within a column', () => {
    expect(flowNeighbour('jump', 'ArrowDown', nodes, edges)).toBe('ci')
    expect(flowNeighbour('ci', 'ArrowUp', nodes, edges)).toBe('jump')
    expect(flowNeighbour('ci', 'ArrowDown', nodes, edges)).toBeNull()
  })

  it('stays put at the ends and jumps with Home and End', () => {
    expect(flowNeighbour('db', 'ArrowRight', nodes, edges)).toBeNull()
    expect(flowNeighbour('entry', 'ArrowLeft', nodes, edges)).toBeNull()
    expect(flowNeighbour('ci', 'Home', nodes, edges)).toBe('entry')
    expect(flowNeighbour('entry', 'End', nodes, edges)).toBe('db')
  })

  it('starts at the first node when nothing is focused, and ignores other keys', () => {
    expect(flowNeighbour(null, 'ArrowRight', nodes, edges)).toBe('entry')
    expect(flowNeighbour('entry', 'a', nodes, edges)).toBeNull()
    expect(flowNeighbour('entry', 'ArrowRight', [], [])).toBeNull()
  })
})
