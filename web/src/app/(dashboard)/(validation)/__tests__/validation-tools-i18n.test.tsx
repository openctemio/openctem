/**
 * The validation tools (compensating controls, control testing, attack
 * simulation, ATT&CK coverage) render in the user's language (Vietnamese here).
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import CompensatingControlsPage from '../controls/page'
import ControlTestingPage from '../control-testing/page'
import AttackSimulationPage from '../attack-simulation/page'
import MitreCoveragePage from '../validation/attack-coverage/page'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('swr', async (orig) => ({
  ...(await orig<typeof import('swr')>()),
  default: vi.fn(() => ({
    data: {
      data: [
        {
          id: 'c1',
          name: 'WAF',
          description: '',
          control_type: 'runtime',
          status: 'active',
          reduction_factor: 0.3,
          last_tested_at: null,
          test_result: null,
          created_at: '',
          updated_at: '',
        },
      ],
      total: 1,
      page: 1,
      per_page: 100,
    },
    isLoading: false,
    mutate: vi.fn(),
  })),
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), del: vi.fn(), patch: vi.fn() }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: { CompensatingControlsWrite: 'x', PentestWrite: 'y' },
}))
vi.mock('@/features/controls/components/link-assets-dialog', () => ({
  LinkAssetsDialog: () => null,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
  useTenantModules: () => ({ moduleIds: ['attack_simulation'] }),
}))
vi.mock('@/features/validation/components/validation-coverage-card', () => ({
  ValidationCoverageCard: () => null,
}))
vi.mock('@/hooks/use-url-param', () => ({ useUrlFilter: () => ['all', vi.fn()] }))
vi.mock('@/features/pentest/api/use-pentest-api', () => ({
  useAllPentestFindings: () => ({ data: { data: [] }, isLoading: false, mutate: vi.fn() }),
}))
vi.mock('@/features/simulation/api/use-simulation-api', () => ({
  useSimulations: () => ({
    data: {
      data: [
        {
          id: 's1',
          name: 'Phishing sim',
          status: 'active',
          simulation_type: 'phishing',
          mitre_technique_id: 'T1566',
          mitre_technique_name: 'Phishing',
          mitre_tactic: 'initial-access',
          last_result: 'bypassed',
          last_run_at: null,
          detection_rate: 40,
          prevention_rate: 10,
        },
      ],
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useRunSimulation: () => ({ trigger: vi.fn() }),
  useControlTests: () => ({
    data: {
      data: [
        {
          id: 't1',
          name: 'MFA test',
          control_id: 'AC-2',
          framework: 'NIST CSF',
          category: '',
          risk_level: 'high',
          status: 'untested',
          last_tested_at: null,
        },
      ],
    },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useControlTestStats: () => ({ data: [], isLoading: false }),
  useCreateControlTest: () => ({ trigger: vi.fn(), isMutating: false }),
  useRecordControlTestResult: () => ({ trigger: vi.fn(), isMutating: false }),
}))

const inVi = (ui: React.ReactNode) => render(<I18nProvider locale="vi">{ui}</I18nProvider>)

describe('validation tools in Vietnamese', () => {
  it('translates the compensating controls page', () => {
    inVi(<CompensatingControlsPage />)
    expect(screen.getByText('Biện pháp bù trừ')).toBeTruthy()
    expect(screen.getByText('Biện pháp mới')).toBeTruthy()
    expect(screen.getByText('Kiểm thử gần nhất')).toBeTruthy()
    expect(screen.getByText('Chưa bao giờ')).toBeTruthy()
    expect(screen.queryByText('Last tested')).toBeNull()
    expect(screen.queryByText('Never')).toBeNull()
  })

  it('translates control testing and shows a dash when nothing is tested', () => {
    inVi(<ControlTestingPage />)
    expect(screen.getByText('Kiểm thử biện pháp')).toBeTruthy()
    expect(screen.getByText('Biện pháp an ninh')).toBeTruthy()
    expect(screen.getByText('Độ phủ')).toBeTruthy()
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    expect(screen.queryByText('Security controls')).toBeNull()
    expect(screen.queryByText('0%')).toBeNull()
  })

  it('translates attack simulation', () => {
    inVi(<AttackSimulationPage />)
    expect(screen.getByText('Mô phỏng tấn công')).toBeTruthy()
    expect(screen.getByText('Tỷ lệ phát hiện trung bình')).toBeTruthy()
    expect(screen.getAllByText('Vượt qua được').length).toBeGreaterThan(0)
    expect(screen.queryByText('Attack simulation')).toBeNull()
    expect(screen.queryByText('Never')).toBeNull()
  })

  it('translates ATT&CK coverage', () => {
    inVi(<MitreCoveragePage />)
    expect(screen.getByText('Độ phủ ATT&CK')).toBeTruthy()
    expect(screen.getByText('Ma trận ATT&CK')).toBeTruthy()
    expect(screen.getByText('Chưa được phủ')).toBeTruthy()
    expect(screen.queryByText('ATT&CK matrix')).toBeNull()
  })
})
