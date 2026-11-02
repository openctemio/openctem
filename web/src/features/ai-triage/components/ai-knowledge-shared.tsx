'use client'

import { TonePill } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'

import type {
  KnowledgeDocumentStatus,
  KnowledgeSource,
  KnowledgeSourceStatus,
} from '../api/use-ai-knowledge'

/** Bytes as a short human size (1024 based). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

/** The text length in UTF-8 bytes, which is what the API caps. */
export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length
}

export function SourceStatusPill({
  status,
  pendingDocuments = 0,
}: {
  status: KnowledgeSourceStatus | KnowledgeDocumentStatus
  pendingDocuments?: number
}) {
  const { t } = useTranslation()
  const detail =
    status === 'approved' && pendingDocuments > 0
      ? t('settings.ai.knowledge.pendingCount', '{count} pending', { count: pendingDocuments })
      : undefined
  switch (status) {
    case 'approved':
      return (
        <TonePill
          tone="success"
          label={t('settings.ai.knowledge.status.approved', 'Approved')}
          detail={detail}
        />
      )
    case 'pending':
      return (
        <TonePill
          tone="warning"
          label={t('settings.ai.knowledge.status.pending', 'Pending approval')}
        />
      )
    case 'rejected':
      return (
        <TonePill
          tone="destructive"
          label={t('settings.ai.knowledge.status.rejected', 'Rejected')}
        />
      )
    case 'superseded':
      return (
        <TonePill tone="muted" label={t('settings.ai.knowledge.status.superseded', 'Replaced')} />
      )
    default:
      return (
        <TonePill tone="muted" label={t('settings.ai.knowledge.status.disabled', 'Disabled')} />
      )
  }
}

export function visibilityText(
  t: ReturnType<typeof useTranslation>['t'],
  s: Pick<KnowledgeSource, 'visibility' | 'team_ids'>
): string {
  return s.visibility === 'teams'
    ? t('settings.ai.knowledge.visibility.teamsCount', '{count} teams', {
        count: s.team_ids.length,
      })
    : t('settings.ai.knowledge.visibility.organization', 'Organization')
}

export function dataClassText(
  t: ReturnType<typeof useTranslation>['t'],
  c: string | undefined
): string {
  return c === 'restricted'
    ? t('settings.ai.knowledge.class.restricted', 'Restricted')
    : t('settings.ai.knowledge.class.internal', 'Internal')
}
