/**
 * The fix plan says what is distinct about each step: one category heading
 * per run, the score only where it changes, and a long plan bounded with
 * "Show more" (no step is lost).
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PosturePlanList, planSections } from '../posture-plan-list'

const step = (i: number, score = 53, grade = 'F') => ({
  asset_id: `0196f0c2-1111-7000-8000-${String(i).padStart(12, '0')}`,
  asset_name: `192.0.2.${i}`,
  category: 'vulnerabilities',
  points: 500,
  issues: 20 + i,
  score_after: score,
  grade_after: grade,
})

describe('PosturePlanList', () => {
  it('shows the category once and the score only on the step that changes it', () => {
    const steps = [step(1), step(2), step(3), step(4, 61, 'D')]
    render(<PosturePlanList steps={steps} currentScore={53} />)
    expect(screen.getAllByText('Vulnerabilities')).toHaveLength(1)
    const scores = screen.getAllByTestId('posture-plan-score')
    expect(scores).toHaveLength(1)
    expect(scores[0]).toHaveTextContent('61')
    // Each row keeps what is its own: the asset and its issue count.
    expect(screen.getByText('21 issues')).toBeInTheDocument()
    expect(screen.getByText('24 issues')).toBeInTheDocument()
  })

  it('bounds a long plan and shows the rest on demand', async () => {
    const steps = Array.from({ length: 25 }, (_, i) => step(i + 1))
    render(<PosturePlanList steps={steps} currentScore={53} />)
    expect(screen.getAllByTestId('posture-plan-step')).toHaveLength(8)
    await userEvent.click(screen.getByRole('button', { name: 'Show 17 more' }))
    expect(screen.getAllByTestId('posture-plan-step')).toHaveLength(25)
  })

  it('starts a new section when the category changes', () => {
    const s = planSections(
      [step(1), { ...step(2), category: 'misconfiguration' }, step(3)],
      undefined
    )
    expect(s.map((x) => x.category)).toEqual([
      'vulnerabilities',
      'misconfiguration',
      'vulnerabilities',
    ])
    // Without a current score the first step shows its score.
    expect(s[0].steps[0].changes).toBe(true)
  })
})
