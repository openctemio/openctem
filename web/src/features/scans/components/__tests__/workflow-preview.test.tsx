import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { WorkflowPreviewBody, type WorkflowPreview } from '../new-scan/workflow-preview'

const base: WorkflowPreview = {
  blocking: false,
  nodes: [
    {
      step_key: 'subdomains',
      name: 'Subdomain discovery',
      capability: 'discover.subdomains@1',
      tier: 'T0',
      tool: 'subfinder',
      pinned: false,
      candidates: ['subfinder'],
      availability: { status: 'ready', sensors_online: 2, sensors_total: 2, sensors_excluded: 0 },
    },
  ],
  targets: { resolved_targets: 3, excluded_targets: 1, uncovered_targets: 0 },
}

describe('WorkflowPreviewBody', () => {
  it('says how many sensors share a chunked step, from the API', () => {
    render(
      <WorkflowPreviewBody
        preview={{
          ...base,
          nodes: [{ ...base.nodes![0], chunk_size: 50, max_parallel_sensors: 2 }],
        }}
      />
    )
    expect(screen.getByTestId('preview-parallel').textContent).toContain('chunks of 50')
    expect(screen.getByTestId('preview-parallel').textContent).toContain('up to 2 sensor(s)')
  })

  it('says nothing about chunks for a one-command step', () => {
    render(<WorkflowPreviewBody preview={base} />)
    expect(screen.queryByTestId('preview-parallel')).toBeNull()
  })

  it('shows each step with its capability, tier, tool and sensors', () => {
    render(<WorkflowPreviewBody preview={base} />)
    expect(screen.getByText('Every step can run.')).toBeInTheDocument()
    expect(screen.getByText('discover.subdomains@1')).toBeInTheDocument()
    expect(screen.getByText('T0')).toBeInTheDocument()
    expect(screen.getByText('picks subfinder')).toBeInTheDocument()
    expect(screen.getByText('ready · 2/2 online')).toBeInTheDocument()
    expect(screen.getByText(/3 target\(s\) resolved, 1 excluded by scope/)).toBeInTheDocument()
  })

  it('shows what the trigger would refuse with, and an active freeze', () => {
    render(
      <WorkflowPreviewBody
        preview={{
          ...base,
          blocking: true,
          freeze: { window: 'Change freeze', until: '2026-10-08T00:00:00Z' },
          nodes: [
            {
              ...base.nodes![0],
              tool: 'checkov',
              pinned: true,
              availability: { status: 'no_sensor', sensors_online: 0, sensors_total: 0 },
              blocking: {
                code: 'NO_SENSOR_FOR_TOOL',
                message: 'Step "iac": No sensor has checkov.',
              },
            },
          ],
        }}
      />
    )
    expect(screen.getByText('The scan would not start as it is')).toBeInTheDocument()
    expect(screen.getByText('Step "iac": No sensor has checkov.')).toBeInTheDocument()
    expect(screen.getByText('runs checkov')).toBeInTheDocument()
    expect(screen.getByText('no sensor')).toBeInTheDocument()
    expect(screen.getByText('Change freeze')).toBeInTheDocument()
  })
})
