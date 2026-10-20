import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemberAccessReportView } from '../member-access-report'
import type { MemberAccessReport } from '../../types/member.types'

const base: MemberAccessReport = {
  membership_id: 'm1',
  user_id: 'u1',
  status: 'active',
  roles: [],
  groups: [],
  api_keys: [],
  campaigns: [],
  direct_grants: 0,
  visible_assets: 0,
  owned_scans: [],
  owned_report_schedules: [],
  owned_workflows: [],
  assigned_findings: 0,
  owned_assets: 0,
}

describe('MemberAccessReportView', () => {
  it('lists the service account keys the member minted and says they are revoked', () => {
    render(
      <MemberAccessReportView
        report={{
          ...base,
          service_account_keys: [
            { id: 'k1', name: 'siem-export', status: 'active', detail: 'SIEM' },
          ],
        }}
      />
    )
    expect(screen.getAllByText('Service account keys').length).toBeGreaterThan(0)
    expect(screen.getByText('siem-export')).toBeInTheDocument()
    expect(screen.getByText(/revoked when the member is offboarded/i)).toBeInTheDocument()
  })
})
