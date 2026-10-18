import { describe, expect, it } from 'vitest'
import { sensorJobFormFrom, sensorLooseningsOf } from '../sensor-job-safety-settings'

describe('sensorLooseningsOf', () => {
  const strict = {
    require_sensor_local_policy_for_private_targets: true,
    allow_sensor_interactsh: false,
    allow_sensor_custom_templates: false,
    tool_http_user_agent: 'scanner',
    forbid_tool_insecure_tls: true,
  }
  it('reports changes that let jobs do more', () => {
    expect(
      sensorLooseningsOf(strict, {
        require_sensor_local_policy_for_private_targets: false,
        allow_sensor_interactsh: true,
        allow_sensor_custom_templates: true,
        tool_http_user_agent: '',
        forbid_tool_insecure_tls: false,
      })
    ).toEqual(['privateTargets', 'interactsh', 'customTemplates', 'insecureTls'])
  })
  it('a User-Agent change or tightening is not a loosening', () => {
    expect(sensorLooseningsOf(strict, { ...strict, tool_http_user_agent: 'other' })).toEqual([])
    expect(sensorLooseningsOf(sensorJobFormFrom(undefined), strict)).toEqual([])
  })
})
