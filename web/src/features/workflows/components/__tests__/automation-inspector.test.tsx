import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import type { AutomationNode } from '../../lib/automation-graph'
import { AutomationInspector, parseConfigJson, parseTags } from '../automation-inspector'

vi.mock('@/lib/api/scan-hooks', () => ({
  useScanConfigs: () => ({ data: { items: [{ id: 's1', name: 'Nightly' }] }, isLoading: false }),
}))

function node(type: string, config: AutomationNode['data']['config']): AutomationNode {
  return {
    id: 'n1',
    type,
    position: { x: 0, y: 0 },
    data: { label: 'Step', nodeKey: 'n1', config },
  }
}

describe('AutomationInspector', () => {
  it('flags a stored run_script action instead of offering it', () => {
    render(
      <AutomationInspector
        node={node('action', { action_type: 'run_script' })}
        onChange={() => {}}
        onDelete={() => {}}
      />
    )
    expect(screen.getByText(/is not supported/)).toBeInTheDocument()
    expect(screen.queryByText('Run Script')).toBeNull()
  })

  it('edits tags as a list', () => {
    const onChange = vi.fn()
    render(
      <AutomationInspector
        node={node('action', { action_type: 'add_tags', action_config: { tags: [] } })}
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

  it('removes the node', () => {
    const onDelete = vi.fn()
    render(
      <AutomationInspector node={node('condition', {})} onChange={() => {}} onDelete={onDelete} />
    )
    fireEvent.click(screen.getByRole('button', { name: /Remove node/ }))
    expect(onDelete).toHaveBeenCalled()
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
