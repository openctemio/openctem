'use client'

/**
 * Who may be invited and whether people from outside need an end of access
 * (api RFC-095 §4), part of the Authentication settings form (saved with its
 * one Save; owner, with a re-authentication).
 */

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'

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
    <Card>
      <CardHeader>
        <CardTitle>{t('org.invitePolicy.title')}</CardTitle>
        <CardDescription>{t('org.invitePolicy.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <RadioGroup
          value={invitees}
          onValueChange={(v) => onInviteesChange(v as InviteesPolicy)}
          disabled={disabled}
          aria-label={t('org.invitePolicy.title')}
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
                <p id={`invitees-${p}-desc`} className="text-xs text-muted-foreground">
                  {t(`org.invitePolicy.${p}Hint`)}
                </p>
              </div>
            </div>
          ))}
        </RadioGroup>
        <div className="flex items-start justify-between gap-4">
          <div>
            <Label htmlFor="external-access-end-required">
              {t('org.invitePolicy.endRequired')}
            </Label>
            <p className="text-xs text-muted-foreground">{t('org.invitePolicy.endRequiredHint')}</p>
          </div>
          <Switch
            id="external-access-end-required"
            checked={endRequired}
            onCheckedChange={onEndRequiredChange}
            disabled={disabled}
          />
        </div>
      </CardContent>
    </Card>
  )
}
