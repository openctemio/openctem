import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PracticeSwitch } from '../practice-switch'

const counts = {
  byPractice: { aspm: 4, infra: 0, compliance: 2, external: 1 },
  vulnerabilities: 5,
  total: 7,
}

describe('PracticeSwitch', () => {
  it('shows Vulnerabilities, Compliance, the practices with findings and All, with counts', () => {
    render(<PracticeSwitch value="vulnerabilities" counts={counts} onChange={() => {}} />)
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent)
    expect(tabs).toEqual([
      'Vulnerabilities5',
      'Compliance2',
      'Application security4',
      'External exposure1',
      'All7',
    ])
    expect(screen.getByRole('tab', { name: /Vulnerabilities/ })).toHaveAttribute(
      'data-state',
      'active'
    )
  })

  it('switches to compliance in one click', async () => {
    const onChange = vi.fn()
    render(<PracticeSwitch value="vulnerabilities" counts={counts} onChange={onChange} />)
    await userEvent.click(screen.getByRole('tab', { name: /Compliance/ }))
    expect(onChange).toHaveBeenCalledWith('compliance')
  })

  it('renders the main tabs before the counts arrive', () => {
    render(<PracticeSwitch value="vulnerabilities" onChange={() => {}} />)
    expect(screen.getAllByRole('tab')).toHaveLength(3)
  })
})
