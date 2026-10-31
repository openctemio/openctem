/**
 * The compliance page loads a framework's controls and assessments (two
 * 200-row lists) only on the Controls tab. The Frameworks tab, the default,
 * shows each framework's own stats and does not need them.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/compliance',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const useFrameworkControls = vi.fn((..._args: unknown[]) => ({ data: undefined, isLoading: false }))
const useAssessments = vi.fn((..._args: unknown[]) => ({ data: undefined }))
vi.mock('@/features/compliance/api/use-compliance-api', () => ({
  useFrameworks: () => ({
    data: { data: [{ id: 'fw1', name: 'Framework one', description: '', total_controls: 3 }] },
    isLoading: false,
  }),
  useComplianceStats: () => ({
    data: { total_frameworks: 1, total_controls: 3, overdue_controls: 0 },
  }),
  useFrameworkStats: () => ({ data: undefined }),
  useFrameworkControls: (...args: unknown[]) => useFrameworkControls(...args),
  useAssessments: (...args: unknown[]) => useAssessments(...args),
  useUpdateAssessment: () => ({ trigger: vi.fn(), isMutating: false }),
}))

import CompliancePage from '../page'

describe('compliance page requests', () => {
  beforeEach(() => {
    useFrameworkControls.mockClear()
    useAssessments.mockClear()
  })

  it('the Frameworks tab asks for no controls or assessments', () => {
    window.history.replaceState(null, '', '/compliance')
    render(<CompliancePage />)
    for (const call of useFrameworkControls.mock.calls) expect(call[0]).toBe('')
    for (const call of useAssessments.mock.calls) expect(call[0]).toBe('')
  })

  it('the Controls tab loads the first framework when none is selected', () => {
    window.history.replaceState(null, '', '/compliance?tab=controls')
    render(<CompliancePage />)
    expect(useFrameworkControls).toHaveBeenLastCalledWith('fw1', 1, 200)
    expect(useAssessments).toHaveBeenLastCalledWith('fw1', 1, 200)
  })

  it('the Controls tab loads the selected framework', () => {
    window.history.replaceState(null, '', '/compliance?tab=controls&framework=fw9')
    render(<CompliancePage />)
    expect(useFrameworkControls).toHaveBeenLastCalledWith('fw9', 1, 200)
    expect(useAssessments).toHaveBeenLastCalledWith('fw9', 1, 200)
  })
})
