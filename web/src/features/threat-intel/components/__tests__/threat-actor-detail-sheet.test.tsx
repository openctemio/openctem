import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { ThreatActor } from '../../api/use-threat-actors-api'
import { ThreatActorDetailSheet } from '../threat-actors-panel'

vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: { ThreatIntelRead: 'threat_intel:read', ThreatIntelWrite: 'threat_intel:write' },
  usePermissions: () => ({ can: () => true }),
}))

// What the API returns for an actor created without TTPs: ttps is null.
const actor = {
  id: 'ta-1',
  name: 'FIN7',
  aliases: [],
  description: 'Financially motivated.',
  actor_type: 'cybercrime',
  is_active: true,
  mitre_group_id: 'G0046',
  ttps: null,
  target_industries: ['Retail'],
  target_regions: ['Europe'],
  external_references: null,
  tags: null,
  created_at: '2026-10-02T00:00:00Z',
  updated_at: '2026-10-02T00:00:00Z',
} as unknown as ThreatActor

describe('ThreatActorDetailSheet', () => {
  it('renders an actor whose list fields are null instead of crashing', () => {
    render(
      <ThreatActorDetailSheet actor={actor} open onOpenChange={() => {}} onDelete={() => {}} />
    )
    expect(screen.getByRole('dialog', { name: 'FIN7' })).toBeInTheDocument()
    expect(screen.getByText('Retail')).toBeInTheDocument()
    expect(screen.queryByText('TTPs')).not.toBeInTheDocument()
  })
})
