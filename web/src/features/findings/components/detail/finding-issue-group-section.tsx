'use client'

/**
 * Same issue in other tools: findings that other tools (or rules) report for
 * this finding's issue, linked without being merged. Each keeps its own
 * status, SLA, ticket and task; the dashboard counts the group once. The list
 * holds only the members the caller may see. A person with triage rights can
 * take a finding out of the group; it is then never linked to it again
 * automatically.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Layers } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Can, Permission } from '@/lib/permissions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { SeverityBadge } from '@/features/shared'
import { MetaLine } from '@/features/shared/components/text-layout'
import type { Severity } from '@/features/shared/types'
import { FindingStatusBadge } from '../finding-status-badge'
import type { FindingStatus } from '../../types'
import {
  unlinkIssue,
  useFindingIssueGroup,
  type FindingIssueGroupMember,
} from '../../api/use-finding-issue-group'

const RULE_KEYS: Record<string, [string, string]> = {
  sast_overlap: [
    'findings.issueGroup.rule.sastOverlap',
    'Same file and asset, overlapping lines, same weakness (CWE)',
  ],
  secret_value: ['findings.issueGroup.rule.secretValue', 'Same secret value'],
  vuln_alias: [
    'findings.issueGroup.rule.vulnAlias',
    'Same vulnerability under another identifier, same asset',
  ],
}

export function FindingIssueGroupSection({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const { members, mutate } = useFindingIssueGroup(findingId)
  const [target, setTarget] = useState<FindingIssueGroupMember | null>(null)
  const [busy, setBusy] = useState(false)

  if (members.length < 2) return null
  const linkRule = members.find((m) => m.rule)?.rule
  const rule = linkRule ? RULE_KEYS[linkRule] : undefined

  const confirmUnlink = async () => {
    if (!target) return
    setBusy(true)
    try {
      await unlinkIssue(findingId, target.id)
      toast.success(t('findings.issueGroup.unlinked', 'Taken out of the group'))
      setTarget(null)
      await mutate()
    } catch (err) {
      toast.error(getErrorMessage(err, t('findings.issueGroup.unlinkFailed', 'Could not unlink')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <DetailSection
      title={t('findings.issueGroup.heading', 'Same issue in other tools')}
      icon={Layers}
      count={members.length}
    >
      <p className="text-sm text-muted-foreground">
        {t(
          'findings.issueGroup.explainer',
          'These findings report one issue. They are linked, not merged: each keeps its own status, and the dashboard counts the group once.'
        )}
      </p>
      {rule && (
        <p className="text-sm">
          <span className="text-muted-foreground">
            {t('findings.issueGroup.whyLinked', 'Why linked')}:{' '}
          </span>
          {t(rule[0], rule[1])}
        </p>
      )}
      <ul className="divide-y rounded-md border">
        {members.map((m) => {
          const self = m.id === findingId
          const location = [
            m.asset_name,
            m.file_path && (
              <span key="path" className="break-all font-mono">
                {m.file_path}
                {m.start_line ? `:${m.start_line}` : ''}
              </span>
            ),
          ]
          return (
            <li
              key={m.id}
              className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  {self ? (
                    <span className="font-medium">{m.title || m.rule_id}</span>
                  ) : (
                    <Link href={`/findings/${m.id}`} className="font-medium hover:underline">
                      {m.title || m.rule_id}
                    </Link>
                  )}
                  {m.is_primary && (
                    <Badge variant="secondary" className="text-xs">
                      {t('findings.issueGroup.primary', 'First reported')}
                    </Badge>
                  )}
                  {self && (
                    <Badge variant="outline" className="text-xs">
                      {t('findings.issueGroup.thisFinding', 'This finding')}
                    </Badge>
                  )}
                </div>
                <MetaLine items={[m.tool_name, m.rule_id]} />
                <MetaLine items={location} />
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                <SeverityBadge severity={m.severity as Severity} />
                <FindingStatusBadge status={m.status as FindingStatus} />
                {!self && (
                  <Can permission={Permission.FindingsTriage}>
                    <Button variant="outline" size="sm" onClick={() => setTarget(m)}>
                      {t('findings.issueGroup.unlink', 'Unlink')}
                    </Button>
                  </Can>
                )}
              </div>
            </li>
          )
        })}
      </ul>
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => !open && setTarget(null)}
        title={t('findings.issueGroup.confirmTitle', 'Unlink this finding?')}
        desc={t(
          'findings.issueGroup.confirmDesc',
          'It leaves the group and is counted on its own again. It will not be linked to this group automatically again. Neither finding changes otherwise.'
        )}
        confirmText={t('findings.issueGroup.unlink', 'Unlink')}
        handleConfirm={confirmUnlink}
        isLoading={busy}
      />
    </DetailSection>
  )
}
