import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { ScanConfig } from '@/lib/api/scan-types'
import { ScanControls } from '../scan-controls'

const postMock = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: vi.fn().mockRejectedValue(Object.assign(new Error('none'), { statusCode: 404 })),
  post: (...a: unknown[]) => postMock(...a),
}))
vi.mock('@/lib/api/scan-hooks', () => ({ invalidateScanConfigsCache: vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

function config(over: Partial<ScanConfig>): ScanConfig {
  return {
    id: 's1',
    tenant_id: 't1',
    name: 'Nightly recon',
    scan_type: 'single',
    targets_per_job: 1,
    schedule_type: 'daily',
    schedule_timezone: 'UTC',
    run_on_tenant_runner: false,
    sensor_preference: 'auto',
    timeout_seconds: 3600,
    max_retries: 0,
    retry_backoff_seconds: 60,
    status: 'active',
    total_runs: 0,
    successful_runs: 0,
    failed_runs: 0,
    created_at: '',
    updated_at: '',
    ...over,
  }
}

describe('ScanControls confirmations', () => {
  beforeEach(() => postMock.mockReset().mockResolvedValue({}))

  it('Run now asks first and posts the trigger only after Run scan', async () => {
    render(<ScanControls config={config({})} />)
    await userEvent.click(screen.getByRole('button', { name: 'Run now' }))
    expect(await screen.findByRole('alertdialog')).toHaveTextContent('Run "Nightly recon" now?')
    expect(postMock).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Run scan' }))
    await waitFor(() => expect(postMock).toHaveBeenCalledWith('/api/v1/scans/s1/trigger', {}))
  })

  it('turning the schedule off posts at once; on asks first', async () => {
    const { rerender } = render(<ScanControls config={config({})} />)
    await userEvent.click(screen.getByRole('button', { name: 'Schedule off' }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() => expect(postMock).toHaveBeenCalledWith('/api/v1/scans/s1/pause', {}))

    postMock.mockClear()
    rerender(<ScanControls config={config({ status: 'paused' })} />)
    await userEvent.click(screen.getByRole('button', { name: 'Schedule on' }))
    expect(await screen.findByRole('alertdialog')).toHaveTextContent(
      'Turn on the schedule of "Nightly recon"?'
    )
    expect(postMock).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Turn on schedule' }))
    await waitFor(() => expect(postMock).toHaveBeenCalledWith('/api/v1/scans/s1/activate', {}))
  })

  it('Enable on a disabled scan asks first', async () => {
    render(<ScanControls config={config({ status: 'disabled' })} />)
    await userEvent.click(screen.getByRole('button', { name: 'Enable' }))
    expect(await screen.findByRole('alertdialog')).toHaveTextContent('Enable "Nightly recon"?')
    expect(postMock).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Enable scan' }))
    await waitFor(() => expect(postMock).toHaveBeenCalledWith('/api/v1/scans/s1/activate', {}))
  })
})
