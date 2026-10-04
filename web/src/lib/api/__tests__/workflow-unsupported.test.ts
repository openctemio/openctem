import { describe, expect, it } from 'vitest'
import {
  WORKFLOW_ACTION_TYPES,
  WORKFLOW_TRIGGER_TYPES,
  WORKFLOW_UNSUPPORTED_ACTION_TYPES,
  WORKFLOW_UNSUPPORTED_TRIGGER_TYPES,
  formatUnsupportedWorkflowFeature,
  getUnsupportedWorkflowFeatures,
  type WorkflowNode,
} from '../workflow-types'

// The API refuses (400) to create, edit or activate a workflow that uses the
// schedule/finding_age triggers or the assign_team/update_priority actions:
// nothing runs them. No picker may offer them; stored workflows are flagged.

function node(config: WorkflowNode['config']): WorkflowNode {
  return {
    id: 'n',
    workflow_id: 'w',
    node_key: 'k',
    node_type: config.trigger_type ? 'trigger' : 'action',
    name: 'n',
    ui_position: { x: 0, y: 0 },
    config,
    created_at: '',
  }
}

describe('workflow picker lists', () => {
  it('never offer a type the platform does not run', () => {
    for (const t of WORKFLOW_UNSUPPORTED_TRIGGER_TYPES) {
      expect(WORKFLOW_TRIGGER_TYPES as readonly string[]).not.toContain(t)
    }
    for (const a of WORKFLOW_UNSUPPORTED_ACTION_TYPES) {
      expect(WORKFLOW_ACTION_TYPES as readonly string[]).not.toContain(a)
    }
  })

  it('match the API unsupported sets exactly', () => {
    expect([...WORKFLOW_UNSUPPORTED_TRIGGER_TYPES].sort()).toEqual(['finding_age', 'schedule'])
    expect([...WORKFLOW_UNSUPPORTED_ACTION_TYPES].sort()).toEqual([
      'assign_team',
      'update_priority',
    ])
  })
})

describe('getUnsupportedWorkflowFeatures', () => {
  it('prefers the API field', () => {
    expect(
      getUnsupportedWorkflowFeatures({ unsupported_features: ['action:assign_team'], nodes: [] })
    ).toEqual(['action:assign_team'])
  })

  it('falls back to the loaded nodes, without duplicates', () => {
    expect(
      getUnsupportedWorkflowFeatures({
        nodes: [
          node({ trigger_type: 'schedule' }),
          node({ action_type: 'update_priority' }),
          node({ action_type: 'update_priority' }),
          node({ action_type: 'update_status' }),
        ],
      })
    ).toEqual(['trigger:schedule', 'action:update_priority'])
  })

  it('is empty for a supported workflow or no graph', () => {
    expect(
      getUnsupportedWorkflowFeatures({
        nodes: [node({ trigger_type: 'manual' }), node({ action_type: 'create_ticket' })],
      })
    ).toEqual([])
    expect(getUnsupportedWorkflowFeatures({})).toEqual([])
  })
})

describe('formatUnsupportedWorkflowFeature', () => {
  it('labels known types and passes unknown ones through', () => {
    expect(formatUnsupportedWorkflowFeature('action:assign_team')).toBe('Assign Team action')
    expect(formatUnsupportedWorkflowFeature('trigger:finding_age')).toBe('Finding Age trigger')
    expect(formatUnsupportedWorkflowFeature('weird')).toBe('weird')
  })
})
