import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

const useEffectiveSlaPolicy = vi.fn()
vi.mock('../../api/use-sla-policies-api', () => ({
  useEffectiveSlaPolicy: (assetId?: string | null) => useEffectiveSlaPolicy(assetId),
}))

import { PriorityClassSla, formatSlaDays, priorityClassDays } from '../priority-class-sla'

const policy = { p0_days: 3, p1_days: 7, p2_days: 21, p3_days: 90 }

describe('PriorityClassSla', () => {
  beforeEach(() => {
    useEffectiveSlaPolicy.mockReset()
  })

  it('states the window the API reports, not a built-in number', () => {
    useEffectiveSlaPolicy.mockReturnValue({ data: policy })
    render(<PriorityClassSla priorityClass="P0" />)
    expect(screen.getByText('SLA: 3 days')).toBeTruthy()
  })

  it('reads the asset policy when an asset is given', () => {
    useEffectiveSlaPolicy.mockReturnValue({ data: policy })
    render(<PriorityClassSla priorityClass="P3" assetId="a-1" variant="sentence" />)
    expect(useEffectiveSlaPolicy).toHaveBeenCalledWith('a-1')
    expect(screen.getByText('fix within 90 days')).toBeTruthy()
  })

  it('renders nothing while loading or when the policy is unreadable', () => {
    useEffectiveSlaPolicy.mockReturnValue({ data: undefined })
    const { container } = render(<PriorityClassSla priorityClass="P1" />)
    expect(container.textContent).toBe('')
  })

  it('maps each class to its window', () => {
    expect(priorityClassDays(policy, 'P1')).toBe(7)
    expect(priorityClassDays(policy, 'P2')).toBe(21)
    expect(priorityClassDays(undefined, 'P2')).toBeUndefined()
    expect(formatSlaDays(1)).toBe('1 day')
  })
})
