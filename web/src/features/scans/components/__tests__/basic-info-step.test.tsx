import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { BasicInfoStep } from '../new-scan/basic-info-step'
import { DEFAULT_NEW_SCAN } from '../../types'

const pipelineCalls: unknown[] = []
vi.mock('@/lib/api/pipeline-hooks', () => ({
  usePipelines: (filters: unknown) => {
    pipelineCalls.push(filters)
    return {
      data: filters
        ? {
            items: [
              {
                id: 'p1',
                name: 'External discovery',
                description: 'subfinder then httpx',
                steps: [
                  { id: 's1', name: 'Subdomains', tool: 'subfinder' },
                  { id: 's2', name: 'Probe', tool: 'httpx' },
                ],
              },
            ],
          }
        : undefined,
      isLoading: false,
    }
  },
}))
vi.mock('@/lib/api/tool-hooks', () => ({
  useTools: () => ({
    data: { items: [{ id: 't1', name: 'trivy', display_name: 'Trivy', is_active: true }] },
    isLoading: false,
  }),
  // Availability unknown: nothing is disabled.
  useToolAvailability: () => ({ data: undefined }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// Radix Select needs these in jsdom.
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

describe('BasicInfoStep', () => {
  beforeEach(() => {
    pipelineCalls.length = 0
  })

  it('single mode asks for a scanner from the tool registry (no fake scan types)', () => {
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} />)
    expect(screen.getByLabelText('Scanner')).toBeInTheDocument()
    expect(screen.queryByText('Full Scan')).not.toBeInTheDocument()
    expect(screen.queryByText('Compliance')).not.toBeInTheDocument()
    // Pipelines are not fetched outside workflow mode.
    expect(pipelineCalls.every((f) => f === undefined)).toBe(true)
  })

  it('choosing a scanner reports its registry name', async () => {
    const onChange = vi.fn()
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={onChange} />)
    await userEvent.click(screen.getByLabelText('Scanner'))
    await userEvent.click(await screen.findByRole('option', { name: 'Trivy' }))
    expect(onChange).toHaveBeenCalledWith({ scannerName: 'trivy' })
  })

  it('workflow mode lists the real pipelines and shows the chosen one’s steps', () => {
    render(
      <BasicInfoStep
        data={{ ...DEFAULT_NEW_SCAN, mode: 'workflow', workflowId: 'p1' }}
        onChange={vi.fn()}
      />
    )
    expect(pipelineCalls.at(-1)).toMatchObject({ is_active: true })
    expect(screen.getAllByText('External discovery').length).toBeGreaterThan(0)
    expect(screen.getByText('1. subfinder')).toBeInTheDocument()
    expect(screen.getByText('2. httpx')).toBeInTheDocument()
    expect(screen.queryByText('Full Reconnaissance')).not.toBeInTheDocument()
  })

  it('Edit (lockMode) does not offer switching between single and workflow', async () => {
    render(<BasicInfoStep data={DEFAULT_NEW_SCAN} onChange={vi.fn()} lockMode />)
    await userEvent.click(screen.getByText('Advanced Options'))
    expect(screen.queryByText('Workflow Scan')).not.toBeInTheDocument()
    expect(screen.getByText('Sensor Preference')).toBeInTheDocument()
  })
})
