import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SegmentedLens } from '../segmented-lens'

const options = [
  { value: 'a', label: 'A' },
  { value: 'b', label: 'B' },
]

describe('SegmentedLens route marker', () => {
  it('marks a route lens so page anatomy does not count it as a row filter', () => {
    render(<SegmentedLens route label="Views" value="a" options={options} onChange={() => {}} />)
    expect(screen.getByTestId('segmented-lens').getAttribute('data-slot')).toBe('route-lens')
  })

  it('leaves a row filter lens unmarked', () => {
    render(<SegmentedLens label="State" value="a" options={options} onChange={() => {}} />)
    expect(screen.getByTestId('segmented-lens').hasAttribute('data-slot')).toBe(false)
  })
})
