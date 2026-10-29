import { beforeAll, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { WorkflowCatalog } from '@/lib/api/workflow-types'
import type { AutomationNode } from '../../lib/automation-graph'
import { AutomationInspector, parseConfigJson, parseTags } from '../automation-inspector'

vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: () => ({ data: { data: [{ id: 's1', name: 'Nightly' }] }, isLoading: false }),
}))

beforeAll(() => {
  Element.prototype.scrollIntoView ??= () => {}
})

const catalog: WorkflowCatalog = {
  triggers: [
    { type: 'manual', allowed: true },
    { type: 'finding_created', allowed: true },
  ],
  actions: [
    { type: 'add_tags', permission: 'findings:write', allowed: true },
    { type: 'update_status', permission: 'findings:write', allowed: true },
    { type: 'trigger_scan', permission: 'scans:execute', allowed: false },
    { type: 'request_false_positive', permission: 'findings:write', allowed: true },
  ],
  notifications: [{ type: 'slack', permission: 'integrations:read', allowed: true }],
}

function node(type: string, config: AutomationNode['data']['config']): AutomationNode {
  return {
    id: 'n1',
    type,
    position: { x: 0, y: 0 },
    data: { label: 'Step', nodeKey: 'n1', config },
  }
}

describe('AutomationInspector', () => {
  it('offers exactly the catalog actions, a disallowed one disabled with its permission', async () => {
    render(
      <AutomationInspector
        node={node('action', { action_type: 'add_tags', action_config: { tags: [] } })}
        catalog={catalog}
        onChange={() => {}}
        onDelete={() => {}}
      />
    )
    await userEvent.click(screen.getByRole('combobox', { name: 'Action' }))
    const options = screen.getAllByRole('option')
    expect(options.map((o) => o.textContent)).toEqual([
      'Add tags',
      'Update status',
      'Trigger scanNeeds scans:execute',
      'Request false positive',
    ])
    const scan = options[2]
    expect(scan).toHaveAttribute('aria-disabled', 'true')
    // Nothing outside the catalog: no removed type is ever offered.
    expect(screen.queryByRole('option', { name: /HTTP Request|Run Script/ })).toBeNull()
  })

  it('shows a stored removed type by id instead of offering it', () => {
    render(
      <AutomationInspector
        node={node('action', { action_type: 'run_script' })}
        catalog={catalog}
        onChange={() => {}}
        onDelete={() => {}}
      />
    )
    expect(screen.getByTestId('inspector-removed-type')).toHaveTextContent(
      'Removed type: run_script'
    )
  })

  it('limits update_status to confirmed and in progress', async () => {
    render(
      <AutomationInspector
        node={node('action', { action_type: 'update_status', action_config: {} })}
        catalog={catalog}
        onChange={() => {}}
        onDelete={() => {}}
      />
    )
    await userEvent.click(screen.getByRole('combobox', { name: 'Set the status to' }))
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual([
      'Confirmed',
      'In progress',
    ])
  })

  it('says a request action only creates a request a person decides', () => {
    render(
      <AutomationInspector
        node={node('action', { action_type: 'request_false_positive', action_config: {} })}
        catalog={catalog}
        onChange={() => {}}
        onDelete={() => {}}
      />
    )
    expect(screen.getByTestId('request-note')).toHaveTextContent(
      'Creates a request; a person decides.'
    )
    expect(screen.getByLabelText('Justification (required)')).toBeInTheDocument()
  })

  it('offers the catalog triggers only', async () => {
    render(
      <AutomationInspector
        node={node('trigger', { trigger_type: 'manual' })}
        catalog={catalog}
        onChange={() => {}}
        onDelete={() => {}}
      />
    )
    await userEvent.click(screen.getByRole('combobox', { name: 'Trigger' }))
    const list = screen.getByRole('listbox')
    expect(
      within(list)
        .getAllByRole('option')
        .map((o) => o.textContent)
    ).toEqual(['Manual', 'Finding created'])
  })

  it('edits tags as a list', () => {
    const onChange = vi.fn()
    render(
      <AutomationInspector
        node={node('action', { action_type: 'add_tags', action_config: { tags: [] } })}
        catalog={catalog}
        onChange={onChange}
        onDelete={() => {}}
      />
    )
    const input = screen.getByLabelText('Tags (comma separated)')
    fireEvent.change(input, { target: { value: 'prod, , urgent' } })
    fireEvent.blur(input)
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        config: { action_type: 'add_tags', action_config: { tags: ['prod', 'urgent'] } },
      })
    )
  })

  it('removes the node, and offers no removal when read-only', () => {
    const onDelete = vi.fn()
    const { rerender } = render(
      <AutomationInspector node={node('condition', {})} onChange={() => {}} onDelete={onDelete} />
    )
    fireEvent.click(screen.getByRole('button', { name: /Remove node/ }))
    expect(onDelete).toHaveBeenCalled()
    rerender(
      <AutomationInspector
        node={node('condition', {})}
        readOnly
        onChange={() => {}}
        onDelete={onDelete}
      />
    )
    expect(screen.queryByRole('button', { name: /Remove node/ })).toBeNull()
  })
})

describe('inspector parsers', () => {
  it('parses tags and JSON objects', () => {
    expect(parseTags(' a, b ,,c ')).toEqual(['a', 'b', 'c'])
    expect(parseConfigJson('')).toEqual({ ok: true, value: {} })
    expect(parseConfigJson('{"x": 1}')).toEqual({ ok: true, value: { x: 1 } })
    expect(parseConfigJson('[1]').ok).toBe(false)
    expect(parseConfigJson('{').ok).toBe(false)
  })
})
