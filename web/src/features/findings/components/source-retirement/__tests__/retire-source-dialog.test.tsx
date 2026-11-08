/**
 * "Stop using this source": the server's preview is shown, a reason is
 * required, critical or known-exploited findings need their own tick, the
 * advanced options map to the API's options, the action is hidden without
 * findings:sources:retire, and a finding sighting names the right source.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { RetirePreview, RetirePreviewResponse } from '../../../api/source-retirement-api'

let previewData: RetirePreviewResponse | undefined
const previewCalls: unknown[] = []
const retireSource = vi.fn()
let canRetire = true

vi.mock('../../../api/source-retirement-api', async (orig) => ({
  ...(await orig<typeof import('../../../api/source-retirement-api')>()),
  useRetirePreview: (source: unknown, options: unknown) => {
    previewCalls.push({ source, options })
    return { data: previewData, error: undefined, isLoading: false, mutate: vi.fn() }
  },
  retireSource: (...a: unknown[]) => retireSource(...a),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { FindingsSourcesRetire: 'findings:sources:retire' },
  usePermissions: () => ({ can: () => canRetire, isLoading: false }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't' } }),
  useCurrentTenantId: () => 't',
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { RetireSourceDialog, retireOptionsOf, validRetireReason } =
  await import('../retire-source-dialog')
const { RetireSourceButton } = await import('../retire-source-button')
const { sightingSource } = await import('../../../api/source-retirement-api')

function preview(over: Partial<RetirePreview> = {}): RetirePreviewResponse {
  return {
    label: 'edge-1 junkscan',
    preview: {
      total: 12,
      archive: 7,
      archive_by_severity: { high: 5, medium: 2 },
      critical_or_kev: 0,
      with_sla: 3,
      corroborated: 4,
      kept_engaged: 1,
      kept_in_progress: 0,
      kept_secret: 0,
      kept_severity_skipped: 0,
      already_closed: 0,
      ...over,
    },
  }
}

const source = { kind: 'sensor_tool' as const, sensor_id: 's1', tool: 'junkscan' }

function renderDialog() {
  return render(<RetireSourceDialog open onOpenChange={() => {}} source={source} />)
}

const confirmButton = () => screen.getByRole('button', { name: 'Stop using this source' })

describe('RetireSourceDialog', () => {
  beforeEach(() => {
    previewData = preview()
    previewCalls.length = 0
    retireSource.mockReset()
    retireSource.mockResolvedValue({
      retirement: { id: 'r1', state: 'active', archived_count: 7, planned_count: 7 },
      preview: previewData.preview,
    })
    canRetire = true
  })

  it('shows what the server counted and needs a reason', async () => {
    renderDialog()
    expect(screen.getByText('Stop using edge-1 junkscan?')).toBeInTheDocument()
    expect(screen.getByTestId('retire-preview')).toHaveTextContent(
      '7 findings only this source reported will be archived as source retired.'
    )
    expect(screen.getByTestId('retire-preview')).toHaveTextContent(
      '4 also reported by another source stay as they are.'
    )
    expect(confirmButton()).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'wrong results all along' } })
    expect(confirmButton()).toBeEnabled()
    fireEvent.click(confirmButton())
    await waitFor(() => expect(retireSource).toHaveBeenCalled())
    expect(retireSource.mock.calls[0][0]).toEqual({
      source,
      options: { mode: 'archive' },
      reason: 'wrong results all along',
      confirm_critical: false,
    })
  })

  it('needs a separate tick for critical or known-exploited findings', async () => {
    previewData = preview({ critical_or_kev: 2 })
    renderDialog()
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'wrong results all along' } })
    expect(confirmButton()).toBeDisabled()
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'I reviewed the 2 critical or known-exploited findings that will be archived.',
      })
    )
    expect(confirmButton()).toBeEnabled()
    fireEvent.click(confirmButton())
    await waitFor(() => expect(retireSource).toHaveBeenCalled())
    expect(retireSource.mock.calls[0][0].confirm_critical).toBe(true)
  })

  it('previews again with the advanced options', () => {
    renderDialog()
    fireEvent.click(screen.getByRole('button', { name: 'Advanced options' }))
    fireEvent.click(
      screen.getByRole('checkbox', { name: 'Keep every finding open; only refuse new data' })
    )
    expect(previewCalls.at(-1)).toEqual({ source, options: { mode: 'keep_open' } })
  })

  it('is hidden without the permission', () => {
    canRetire = false
    render(<RetireSourceButton source={source} />)
    expect(screen.queryByRole('button', { name: 'Stop using this source' })).toBeNull()
  })
})

describe('retire options and sources', () => {
  it('sends only what differs from the defaults', () => {
    expect(retireOptionsOf(false, ['critical', 'high', 'medium', 'low', 'info'], false)).toEqual({
      mode: 'archive',
    })
    expect(retireOptionsOf(false, ['critical', 'high'], true)).toEqual({
      mode: 'archive',
      severities: ['critical', 'high'],
      include_engaged: true,
    })
    expect(retireOptionsOf(true, ['critical'], true)).toEqual({ mode: 'keep_open' })
  })

  it('checks the reason length', () => {
    expect(validRetireReason('short')).toBe(false)
    expect(validRetireReason('  long enough reason  ')).toBe(true)
    expect(validRetireReason('x'.repeat(501))).toBe(false)
  })

  it('names the source of a sighting', () => {
    expect(sightingSource({ channel: 'scan', sensor: { id: 's1' }, tool: 'nuclei' })).toEqual({
      kind: 'sensor_tool',
      sensor_id: 's1',
      tool: 'nuclei',
    })
    expect(sightingSource({ channel: 'upload', tool: 'nessus' })).toEqual({
      kind: 'upload',
      tool: 'nessus',
    })
    expect(sightingSource({ channel: 'connector', sender: 'feed' })).toEqual({
      kind: 'connector',
      sender: 'feed',
    })
    // A shared platform sensor, CI and the platform matcher are not retired here.
    expect(sightingSource({ channel: 'scan', sender: 'platform', tool: 'nuclei' })).toBeNull()
    expect(sightingSource({ channel: 'ci', sender: 'org/repo', tool: 'semgrep' })).toBeNull()
    expect(sightingSource({ channel: 'platform', tool: 'version-match' })).toBeNull()
  })
})
