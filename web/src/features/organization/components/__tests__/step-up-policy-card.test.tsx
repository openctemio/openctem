import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import {
  LEGACY_STEP_UP,
  StepUpPolicyCard,
  choiceOf,
  isChoiceAllowed,
  ruleOf,
  stepUpLooser,
} from '../step-up-policy-card'
import { looseningsOf, signInFormFrom } from '../authentication-settings'
import type { StepUpPolicy } from '../../types/settings.types'

describe('re-verification policy', () => {
  it('maps rules to choices and back', () => {
    expect(choiceOf({ mode: 'every_time' })).toBe('every_time')
    expect(choiceOf({ mode: 'off' })).toBe('off')
    expect(choiceOf({ mode: 'once_per_window', window: '4h' })).toBe('4h')
    expect(ruleOf('session')).toEqual({ mode: 'once_per_window', window: 'session' })
    expect(ruleOf('off')).toEqual({ mode: 'off' })
  })

  it('allows critical only every time or once per 10 minutes (the platform floor)', () => {
    expect(isChoiceAllowed('critical', 'every_time')).toBe(true)
    expect(isChoiceAllowed('critical', '10m')).toBe(true)
    for (const c of ['1h', '4h', '8h', 'session', 'off'] as const) {
      expect(isChoiceAllowed('critical', c)).toBe(false)
    }
    expect(isChoiceAllowed('sensitive', 'off')).toBe(true)
    expect(isChoiceAllowed('routine', 'off')).toBe(true)
  })

  it('flags a policy that asks less often as a loosening to confirm', () => {
    const looser: StepUpPolicy = { ...LEGACY_STEP_UP, sensitive: { mode: 'off' } }
    expect(stepUpLooser(LEGACY_STEP_UP, looser)).toBe(true)
    expect(stepUpLooser(looser, LEGACY_STEP_UP)).toBe(false)
    const stricter: StepUpPolicy = { ...LEGACY_STEP_UP, critical: { mode: 'every_time' } }
    expect(stepUpLooser(LEGACY_STEP_UP, stricter)).toBe(false)

    const saved = signInFormFrom(undefined)
    expect(saved.step_up).toEqual(LEGACY_STEP_UP)
    expect(looseningsOf(saved, { ...saved, step_up: looser })).toContain('stepUpLooser')
  })

  it('shows every tier with its explanation, and is read-only for non-owners', () => {
    render(<StepUpPolicyCard policy={LEGACY_STEP_UP} onChange={vi.fn()} disabled />)
    expect(screen.getByText('Re-verification')).toBeInTheDocument()
    expect(screen.getByText('Critical actions')).toBeInTheDocument()
    expect(screen.getByText('Sensitive actions')).toBeInTheDocument()
    expect(screen.getByText('Routine actions')).toBeInTheDocument()
    expect(screen.getByTestId('step-up-floor')).toBeInTheDocument()
    for (const tier of ['critical', 'sensitive', 'routine']) {
      expect(screen.getByTestId(`step-up-${tier}`)).toBeDisabled()
    }
  })
})
