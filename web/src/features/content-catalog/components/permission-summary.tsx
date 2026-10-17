'use client'

import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import type { ContentPackagePermissions, ContentPackageVersion } from '@/lib/api/generated'
import { Badge } from '@/components/ui/badge'
import { DetailField, DetailFieldGrid } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import type { PermissionDiff } from '../lib'

const WIDER = 'rounded-sm bg-warning/15 px-1 font-medium text-warning'

function Values({ values, fresh }: { values?: string[] | null; fresh?: string[] }) {
  const { t } = useTranslation()
  if (!values?.length) {
    return <span className="text-muted-foreground">{t('contentCatalog.none', 'None')}</span>
  }
  return (
    <ul className="flex flex-wrap gap-1">
      {values.map((v) => {
        const isNew = fresh?.includes(v)
        return (
          <li key={v}>
            <Badge variant="outline" className={cn('font-mono text-xs', isNew && WIDER)}>
              {v}
              {isNew && <span className="sr-only">{t('contentCatalog.diff.new', '(new)')}</span>}
            </Badge>
          </li>
        )
      })}
    </ul>
  )
}

function Level({ value, wider }: { value?: string; wider?: boolean }) {
  const { t } = useTranslation()
  return (
    <span className={cn('font-mono text-sm', wider && WIDER)}>
      {value || '-'}
      {wider && <span className="sr-only">{t('contentCatalog.diff.wider', '(wider)')}</span>}
    </span>
  )
}

/** Tier, side effects, network, hosts, credentials and data scopes; wider fields highlighted. */
export function PermissionSummary({
  permissions,
  diff,
}: {
  permissions: ContentPackagePermissions | undefined
  diff?: PermissionDiff
}) {
  const { t } = useTranslation()
  const p = permissions ?? {}
  return (
    <DetailFieldGrid>
      <DetailField label={t('contentCatalog.perm.tier', 'Tier')}>
        <Level value={p.tier} wider={diff?.tier} />
      </DetailField>
      <DetailField label={t('contentCatalog.perm.sideEffects', 'Side effects')}>
        <Level value={p.side_effects} wider={diff?.sideEffects} />
      </DetailField>
      <DetailField label={t('contentCatalog.perm.network', 'Network')}>
        <Level value={p.network} wider={diff?.network} />
      </DetailField>
      <DetailField label={t('contentCatalog.perm.hosts', 'Declared hosts')} full>
        <Values values={p.declared_hosts} fresh={diff?.newHosts} />
      </DetailField>
      <DetailField label={t('contentCatalog.perm.credentials', 'Credentials')} full>
        <Values values={p.credentials} fresh={diff?.newCredentials} />
      </DetailField>
      <DetailField label={t('contentCatalog.perm.dataScopes', 'Data scopes')} full>
        <Values values={p.data_scopes} fresh={diff?.newDataScopes} />
      </DetailField>
    </DetailFieldGrid>
  )
}

/** SPDX id plus the two license flags; "no service use" stands out. */
export function LicenseSummary({ version }: { version: ContentPackageVersion }) {
  const { t } = useTranslation()
  const l = version.license ?? {}
  return (
    <DetailFieldGrid>
      <DetailField label={t('contentCatalog.license.spdx', 'License')}>
        <span className="font-mono text-sm">{l.spdx || '-'}</span>
      </DetailField>
      <DetailField label={t('contentCatalog.license.serviceUse', 'Use as a service')}>
        {l.service_use ? (
          <Badge variant="secondary">{t('contentCatalog.license.allowed', 'Allowed')}</Badge>
        ) : (
          <Badge variant="outline" className="border-warning text-warning">
            {t('contentCatalog.license.notAllowed', 'Not allowed')}
          </Badge>
        )}
      </DetailField>
      <DetailField label={t('contentCatalog.license.redistribution', 'Redistribution')}>
        {l.redistribution
          ? t('contentCatalog.license.allowed', 'Allowed')
          : t('contentCatalog.license.notAllowed', 'Not allowed')}
      </DetailField>
    </DetailFieldGrid>
  )
}

/** A digest or identity in full, with a copy button that says what it copies. */
export function CopyValue({ value, label }: { value?: string; label: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="text-muted-foreground">-</span>
  return (
    <span className="flex min-w-0 items-start gap-1.5">
      <code className="min-w-0 font-mono text-xs break-all">{value}</code>
      <button
        type="button"
        className="shrink-0 rounded-sm text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        aria-label={t('contentCatalog.copy', 'Copy {label}', { label })}
        onClick={() => {
          void copyToClipboard(value).then((ok) => {
            if (!ok) return
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          })
        }}
      >
        {copied ? (
          <Check className="size-3.5" aria-hidden />
        ) : (
          <Copy className="size-3.5" aria-hidden />
        )}
      </button>
      <span className="sr-only" aria-live="polite">
        {copied ? t('contentCatalog.copied', 'Copied') : ''}
      </span>
    </span>
  )
}
