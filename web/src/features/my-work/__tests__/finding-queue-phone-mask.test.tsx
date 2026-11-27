import { render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { ApiFinding } from '@/features/findings/api/finding-api.types'

let mobileRow: ((f: ApiFinding) => ReactNode) | undefined

vi.mock('@/features/shared', () => ({
  DataTable: (p: { mobileRow: (f: ApiFinding) => ReactNode }) => {
    mobileRow = p.mobileRow
    return null
  },
  DataTableColumnHeader: () => null,
}))
vi.mock('@/features/shared/components/queue', () => ({
  QueueCard: (p: { title: ReactNode }) => <div data-testid="card">{p.title}</div>,
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/components/link', () => ({
  default: (p: { children: ReactNode }) => <a>{p.children}</a>,
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}))

import { FindingQueue } from '../components/finding-queue'

const AWS = 'AKIAIOSFODNN7EXAMPLE'

describe('FindingQueue phone card', () => {
  it('masks a secret in the finding title, in the text and in its hover title', () => {
    render(
      <FindingQueue
        tab="assigned"
        rows={[]}
        total={0}
        isLoading={false}
        error={null}
        onRetry={() => {}}
        empty={null}
      />
    )
    expect(mobileRow).toBeDefined()
    const f = { id: 'f1', title: `Key ${AWS} in config.yml`, severity: 'high' } as ApiFinding
    const { container } = render(<>{mobileRow!(f)}</>)
    const card = container.querySelector('[data-testid="card"]')!
    expect(card.textContent).toContain('config.yml')
    expect(card.textContent).not.toContain(AWS)
    expect(card.innerHTML).not.toContain(AWS)
  })
})
