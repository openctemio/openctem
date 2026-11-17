'use client'

/**
 * Re-verification (step-up) policy, part of the Authentication settings form
 * (saved with its one Save; owner only). API docs:
 * architecture/step-up-reauth.md.
 *
 * Every action behind re-verification belongs to one tier:
 * - critical: roles, sign-in, credentials, secrets, deleting, approving
 *   active scanning, exports. Every time or once per 10 minutes, never off
 *   (the platform floor: the API refuses less, the options are disabled here);
 * - sensitive: governance settings, approving false positives and accepted
 *   risk, closing several findings at once;
 * - routine: one finding's status.
 */

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsBlock, SettingsRow, SettingsSection } from '@/features/shared'
import type { StepUpPolicy, StepUpRule, StepUpWindow } from '../types/settings.types'

export type StepUpTier = keyof StepUpPolicy

/** One select value per rule: every_time, off, or a window. */
export type StepUpChoice = 'every_time' | StepUpWindow | 'off'

/** The choices from the most to the least demanding. */
export const STEP_UP_CHOICES: StepUpChoice[] = [
  'every_time',
  '10m',
  '1h',
  '4h',
  '8h',
  'session',
  'off',
]

/** The choices the platform floor allows for critical actions. */
const CRITICAL_ALLOWED: StepUpChoice[] = ['every_time', '10m']

/** What the API applies to an organization that never saved a policy. */
export const LEGACY_STEP_UP: StepUpPolicy = {
  critical: { mode: 'once_per_window', window: '10m' },
  sensitive: { mode: 'once_per_window', window: '10m' },
  routine: { mode: 'off' },
}

export function choiceOf(rule: StepUpRule | undefined): StepUpChoice {
  if (!rule) return 'off'
  if (rule.mode === 'once_per_window') return rule.window ?? '10m'
  return rule.mode
}

export function ruleOf(choice: StepUpChoice): StepUpRule {
  if (choice === 'every_time' || choice === 'off') return { mode: choice }
  return { mode: 'once_per_window', window: choice }
}

export function isChoiceAllowed(tier: StepUpTier, choice: StepUpChoice): boolean {
  return tier !== 'critical' || CRITICAL_ALLOWED.includes(choice)
}

/** Whether `next` asks less often than `saved` for any tier. */
export function stepUpLooser(saved: StepUpPolicy, next: StepUpPolicy): boolean {
  return (['critical', 'sensitive', 'routine'] as StepUpTier[]).some(
    (tier) =>
      STEP_UP_CHOICES.indexOf(choiceOf(next[tier])) > STEP_UP_CHOICES.indexOf(choiceOf(saved[tier]))
  )
}

export interface StepUpPolicyCardProps {
  policy: StepUpPolicy
  onChange: (p: StepUpPolicy) => void
  disabled?: boolean
}

export function StepUpPolicyCard({ policy, onChange, disabled }: StepUpPolicyCardProps) {
  const { t } = useTranslation()
  return (
    <SettingsSection
      framed
      id="re-verification"
      title={t('org.auth.stepUp.title', 'Re-verification')}
      description={t(
        'org.auth.stepUp.desc',
        'How often people confirm their identity again (authenticator code, password or a new sign-in) before an action. One confirmation counts for every tier until its own time runs out.'
      )}
    >
      {(['critical', 'sensitive', 'routine'] as StepUpTier[]).map((tier) => {
        const id = `step-up-${tier}`
        return (
          <SettingsRow
            key={tier}
            wide
            label={<label htmlFor={id}>{t(`org.auth.stepUp.${tier}`)}</label>}
            hint={t(`org.auth.stepUp.${tier}Hint`)}
            hintId={`${id}-hint`}
          >
            <Select
              value={choiceOf(policy[tier])}
              onValueChange={(v) => onChange({ ...policy, [tier]: ruleOf(v as StepUpChoice) })}
              disabled={disabled}
            >
              <SelectTrigger
                id={id}
                data-testid={id}
                aria-describedby={`${id}-hint`}
                className="w-full"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STEP_UP_CHOICES.map((choice) => (
                  <SelectItem key={choice} value={choice} disabled={!isChoiceAllowed(tier, choice)}>
                    {t(`org.auth.stepUp.choice.${choice}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </SettingsRow>
        )
      })}
      <SettingsBlock>
        <p className="text-cap text-muted-foreground" data-testid="step-up-floor">
          {t(
            'org.auth.stepUp.floor',
            'Critical actions cannot be set to longer than 10 minutes or turned off: they protect who controls the organization.'
          )}
        </p>
      </SettingsBlock>
    </SettingsSection>
  )
}
