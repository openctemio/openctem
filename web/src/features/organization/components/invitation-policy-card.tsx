'use client'

/**
 * Who may be invited and whether people from outside need an end of access
 * (api RFC-095 §4): rows of "Who may join" on the Joining tab of Settings ›
 * Sign-in (saved with that tab's save bar; owner, with a re-authentication).
 */

import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsBlock, SettingsSwitchRow } from '@/features/shared'

import type { InviteesPolicy } from '../types/settings.types'

const POLICIES: InviteesPolicy[] = ['any', 'verified_domains', 'allow_list']

export interface InvitationPolicyCardProps {
  invitees: InviteesPolicy
  onInviteesChange: (p: InviteesPolicy) => void
  endRequired: boolean
  onEndRequiredChange: (v: boolean) => void
  /** allow_list needs at least one allowed domain (Access restrictions). */
  hasAllowedDomains: boolean
  disabled?: boolean
}

export function InvitationPolicyCard({
  invitees,
  onInviteesChange,
  endRequired,
  onEndRequiredChange,
  hasAllowedDomains,
  disabled,
}: InvitationPolicyCardProps) {
  const { t } = useTranslation()
  return (
    <>
      <SettingsBlock id="invitations">
        <p id="invitees-label" className="text-body font-medium">
          {t('org.invitePolicy.title')}
        </p>
        <RadioGroup
          value={invitees}
          onValueChange={(v) => onInviteesChange(v as InviteesPolicy)}
          disabled={disabled}
          aria-labelledby="invitees-label"
          className="gap-3"
        >
          {POLICIES.map((p) => (
            <div key={p} className="flex items-start gap-3">
              <RadioGroupItem
                id={`invitees-${p}`}
                value={p}
                className="mt-0.5"
                disabled={disabled || (p === 'allow_list' && !hasAllowedDomains)}
                aria-describedby={`invitees-${p}-desc`}
              />
              <div>
                <Label htmlFor={`invitees-${p}`}>{t(`org.invitePolicy.${p}`)}</Label>
                <p id={`invitees-${p}-desc`} className="text-cap text-muted-foreground">
                  {t(`org.invitePolicy.${p}Hint`)}
                </p>
              </div>
            </div>
          ))}
        </RadioGroup>
      </SettingsBlock>
      <SettingsSwitchRow
        id="external-access-end-required"
        label={t('org.invitePolicy.endRequired')}
        hint={t('org.invitePolicy.endRequiredHint')}
        checked={endRequired}
        onCheckedChange={onEndRequiredChange}
        disabled={disabled}
      />
    </>
  )
}
