'use client'

import { useEffect, useId, useState } from 'react'
import { Globe, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState } from '@/features/shared/components/empty-state'

import {
  saveDomainSignupPolicy,
  useDomainSignupPolicies,
  type DomainSignupPolicy,
  type DomainSignupPolicyInput,
  type JoinPolicy,
  type JoinRole,
} from '../api/use-domain-signup'

interface Props {
  canRead: boolean
  isOwner: boolean
}

/**
 * Settings > Domains (api RFC-104): for each verified single sign-on domain,
 * who may join with an address on it, whether colleagues see the organization
 * while they sign up, and whether accounts on it must use SSO or may create
 * organizations. Everything is off by default; owners change it.
 */
export function DomainSignupPolicies({ canRead, isOwner }: Props) {
  const { t } = useTranslation()
  const { domains, isLoading, mutate } = useDomainSignupPolicies(canRead)

  if (!canRead) return null
  if (isLoading) {
    return (
      <div
        className="flex justify-center py-12"
        role="status"
        aria-label={t('settings.domains.loading')}
      >
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    )
  }
  const sso = domains.filter((d) => d.purpose === 'sso')
  if (sso.length === 0) {
    return (
      <EmptyState
        icon={Globe}
        title={t('settings.domains.emptyTitle')}
        description={t('settings.domains.emptyDesc')}
      />
    )
  }
  return (
    <div className="space-y-4">
      {sso.map((d) => (
        <DomainCard key={d.id} domain={d} isOwner={isOwner} onSaved={() => void mutate()} />
      ))}
    </div>
  )
}

function toInput(d: DomainSignupPolicy): DomainSignupPolicyInput {
  return {
    join_policy: d.join_policy,
    join_role: d.join_role,
    discoverable: d.discoverable,
    sso_required: d.sso_required,
    block_new_workspaces: d.block_new_workspaces,
    include_subdomains: d.include_subdomains,
  }
}

function DomainCard({
  domain,
  isOwner,
  onSaved,
}: {
  domain: DomainSignupPolicy
  isOwner: boolean
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [value, setValue] = useState<DomainSignupPolicyInput>(toInput(domain))
  const [busy, setBusy] = useState(false)
  useEffect(() => setValue(toInput(domain)), [domain])

  const disabled = !isOwner || !domain.effective || busy
  const dirty = JSON.stringify(value) !== JSON.stringify(toInput(domain))
  const set = <K extends keyof DomainSignupPolicyInput>(k: K, v: DomainSignupPolicyInput[K]) =>
    setValue((cur) => ({ ...cur, [k]: v }))

  const save = async () => {
    setBusy(true)
    try {
      await saveDomainSignupPolicy(domain.id, value)
      toast.success(t('settings.domains.saved', undefined, { domain: domain.domain }))
      onSaved()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('settings.domains.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  const toggle = (
    key: 'discoverable' | 'sso_required' | 'block_new_workspaces' | 'include_subdomains'
  ) => (
    <div className="flex items-start justify-between gap-4">
      <Label htmlFor={`${id}-${key}`} className="grid gap-1 font-normal">
        <span>{t(`settings.domains.${key}`)}</span>
        <span className="text-xs text-muted-foreground">{t(`settings.domains.${key}Hint`)}</span>
      </Label>
      <Switch
        id={`${id}-${key}`}
        checked={value[key]}
        onCheckedChange={(v) => set(key, v)}
        disabled={disabled}
      />
    </div>
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          {domain.domain}
          <Badge variant={domain.effective ? 'default' : 'secondary'}>
            {domain.effective ? t('settings.domains.verified') : t('settings.domains.notEffective')}
          </Badge>
        </CardTitle>
        {!domain.effective && (
          <CardDescription>{t('settings.domains.notEffectiveHint')}</CardDescription>
        )}
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="space-y-2">
          <p className="text-sm font-medium">
            {t('settings.domains.whoCanJoin', undefined, { domain: domain.domain })}
          </p>
          <RadioGroup
            value={value.join_policy}
            onValueChange={(v) => set('join_policy', v as JoinPolicy)}
            disabled={disabled}
            aria-label={t('settings.domains.whoCanJoin', undefined, { domain: domain.domain })}
          >
            {(['off', 'approval', 'auto'] as JoinPolicy[]).map((p) => (
              <div key={p} className="flex items-center gap-2">
                <RadioGroupItem value={p} id={`${id}-join-${p}`} />
                <Label htmlFor={`${id}-join-${p}`} className="font-normal">
                  {t(`settings.domains.join.${p}`)}
                </Label>
              </div>
            ))}
          </RadioGroup>
          {value.join_policy !== 'off' && (
            <div className="flex flex-wrap items-center gap-2 ps-6">
              <span className="text-sm text-muted-foreground">
                {t('settings.domains.joinRole')}
              </span>
              <Select
                value={value.join_role}
                onValueChange={(v) => set('join_role', v as JoinRole)}
                disabled={disabled}
              >
                <SelectTrigger className="h-8 w-32" aria-label={t('settings.domains.joinRole')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="viewer">{t('settings.domains.role.viewer')}</SelectItem>
                  <SelectItem value="member">{t('settings.domains.role.member')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}
        </div>
        {toggle('discoverable')}
        {toggle('sso_required')}
        {toggle('block_new_workspaces')}
        {toggle('include_subdomains')}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">
            {isOwner ? t('settings.domains.stepUpHint') : t('settings.domains.ownerOnly')}
          </p>
          {isOwner && (
            <Button size="sm" onClick={() => void save()} disabled={!dirty || disabled}>
              {busy && <Loader2 className="me-1.5 h-4 w-4 animate-spin" />}
              {t('settings.domains.save')}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
