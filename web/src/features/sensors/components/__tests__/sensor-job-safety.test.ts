import { describe, expect, it } from 'vitest'
import { sensorJobFormFrom, sensorLooseningsOf } from '../sensor-job-safety-settings'

describe('sensorLooseningsOf', () => {
  const strict = {
    require_sensor_local_policy_for_private_targets: true,
    allow_sensor_interactsh: false,
    allow_sensor_custom_templates: false,
    forbid_tool_insecure_tls: true,
  }
  it('reports changes that let jobs do more', () => {
    expect(
      sensorLooseningsOf(strict, {
        require_sensor_local_policy_for_private_targets: false,
        allow_sensor_interactsh: true,
        allow_sensor_custom_templates: true,
        forbid_tool_insecure_tls: false,
      })
    ).toEqual(['privateTargets', 'interactsh', 'customTemplates', 'insecureTls'])
  })
  it('a tightening is not a loosening', () => {
    expect(sensorLooseningsOf(sensorJobFormFrom(undefined), strict)).toEqual([])
  })
})
