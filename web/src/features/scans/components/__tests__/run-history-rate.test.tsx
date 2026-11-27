/**
 * Recent runs: the run glyphs, then the success rate once enough runs count.
 * With fewer runs there is no rate at all, not a hand-written "-" (acceptance
 * review: "Recent runs is a dot and -").
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { RunHistory } from '../run-history'

const run = (i: number, status = 'completed') => ({
  id: `r${i}`,
  status,
  created_at: `2026-11-1${i}T08:00:00Z`,
})

function draw(runs: ReturnType<typeof run>[]) {
  return render(
    <TooltipProvider>
      <RunHistory runs={runs} />
    </TooltipProvider>
  )
}

describe('RunHistory rate', () => {
  it('shows no placeholder dash while too few runs count', () => {
    draw([run(1)])
    const cell = screen.getByRole('img')
    expect(cell.textContent?.trim()).toBe('')
    expect(cell.textContent).not.toMatch(/[-–—]/)
  })

  it('shows the success rate once three runs count', () => {
    draw([run(1), run(2), run(3, 'failed')])
    expect(screen.getByRole('img').textContent).toMatch(/\d+%/)
  })
})
