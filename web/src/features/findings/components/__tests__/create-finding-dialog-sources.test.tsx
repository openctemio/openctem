import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'

const sourcesHook = vi.fn((_config?: unknown, _enabled?: boolean) => ({
  data: undefined,
  isLoading: false,
}))

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (_k: string, d?: string) => d ?? _k }),
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssets: () => ({ assets: [], isLoading: false }),
}))
vi.mock('../../api/use-findings-api', () => ({
  useCreateFindingApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateFindingsCache: vi.fn(),
}))
vi.mock('@/features/config/api', () => ({
  useFindingSourcesApi: (c?: unknown, e?: boolean) => sourcesHook(c, e),
  groupFindingSourcesByCategory: () => new Map(),
}))

import { CreateFindingDialog } from '../create-finding-dialog'

describe('CreateFindingDialog', () => {
  beforeEach(() => sourcesHook.mockClear())

  it('does not ask for the source catalog while it is closed', () => {
    render(<CreateFindingDialog open={false} onOpenChange={() => {}} />)
    expect(sourcesHook.mock.calls.every(([, enabled]) => enabled === false)).toBe(true)
  })

  it('asks for the source catalog once it opens', () => {
    render(<CreateFindingDialog open onOpenChange={() => {}} />)
    expect(sourcesHook.mock.calls.some(([, enabled]) => enabled === true)).toBe(true)
  })
})
