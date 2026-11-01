'use client'

import { useState } from 'react'
import { Plus, ScanSearch, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, ErrorState, GatedButton, PageStack, RelativeTime } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

import {
  deleteContentRule,
  invalidateContentRules,
  updateContentRule,
  useContentRules,
} from '../api/use-content-rules'
import type { ContentRule } from '../types'
import { ContentRuleDialog } from './content-rule-dialog'

/** Settings, Scanning, Detection rules. Reading needs scans:content:read, changes scans:content:write. */
export function ContentRulesPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.ContentPacksRead)
  const canWrite = can(Permission.ContentPacksWrite)
  const { data, error, isLoading, mutate } = useContentRules(canRead)
  const [editing, setEditing] = useState<ContentRule | 'new' | null>(null)
  const [deleting, setDeleting] = useState<ContentRule | null>(null)
  const [toggling, setToggling] = useState<string | null>(null)
  const rules = data?.items ?? []
  const platform = data?.platform ?? []
  const atLimit = !!data && rules.length >= data.limit
  const noWrite = t(
    'contentRules.noWrite',
    'You need the scans:content:write permission to change detection rules'
  )
  const kindLabel = (k: string) =>
    k === 'secret-rules'
      ? t('contentRules.kind.secret-rules', 'Sensitive data')
      : t('contentRules.kind.web-fingerprints', 'Technology')

  if (error) {
    return (
      <ErrorState
        title={t('contentRules.title', 'Detection rules')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading) return <Skeleton className="h-48 w-full" />

  async function toggle(r: ContentRule, enabled: boolean) {
    setToggling(r.id)
    try {
      await updateContentRule(r.id, { enabled })
      await invalidateContentRules()
    } catch (e) {
      toast.error(getErrorMessage(e, t('contentRules.toast.saveFailed', 'Could not save the rule')))
    } finally {
      setToggling(null)
    }
  }

  return (
    <PageStack data-testid="content-rules-panel">
      <Card>
        <CardHeader className="space-y-1">
          <CardTitle className="text-base">
            {t('contentRules.platform.title', 'Platform rules')}
          </CardTitle>
          <CardDescription>
            {t(
              'contentRules.platform.description',
              'Curated by the platform and updated with it. Every scan result is matched with them and with your rules.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {platform.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('contentRules.platform.none', 'No platform rule pack is installed yet.')}
            </p>
          ) : (
            <ul className="space-y-2 text-sm" data-testid="content-rule-packs">
              {platform.map((p) => (
                <li key={p.digest} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <Badge variant="secondary" className="font-normal">
                    {kindLabel(p.kind)}
                  </Badge>
                  <span className="font-medium">{p.pack}</span>
                  <span className="tabular-nums">{p.version}</span>
                  <span className="text-muted-foreground">
                    {t('contentRules.platform.rules', '{count} rules', { count: p.rules })}
                  </span>
                  <code className="text-xs break-all text-muted-foreground">
                    {p.digest.slice(0, 19)}
                  </code>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2 space-y-0">
          <div className="space-y-1">
            <CardTitle className="text-base">
              {t('contentRules.yours.title', 'Your rules')}
            </CardTitle>
            <CardDescription>
              {t(
                'contentRules.yours.description',
                'Name your own products, or find your own key formats and internal names. They apply to your organization only.'
              )}
            </CardDescription>
          </div>
          <GatedButton
            allowed={canWrite && !atLimit}
            reason={
              canWrite
                ? t('contentRules.atLimit', 'An organization has at most {count} rules', {
                    count: data?.limit ?? 0,
                  })
                : noWrite
            }
            size="sm"
            onClick={() => setEditing('new')}
          >
            <Plus className="size-4" aria-hidden />
            {t('contentRules.new', 'New rule')}
          </GatedButton>
        </CardHeader>
        <CardContent>
          {rules.length === 0 ? (
            <EmptyState
              icon={ScanSearch}
              title={t('contentRules.emptyTitle', 'No rules yet')}
              description={t(
                'contentRules.emptyDescription',
                'Platform rules already run on every scan. Add a rule to recognize a product of your own or a key format only your organization uses.'
              )}
            />
          ) : (
            <Table data-testid="content-rules-table">
              <TableHeader>
                <TableRow>
                  <TableHead>{t('contentRules.col.rule', 'Rule')}</TableHead>
                  <TableHead>{t('contentRules.col.kind', 'Kind')}</TableHead>
                  <TableHead className="text-end">
                    {t('contentRules.col.version', 'Version')}
                  </TableHead>
                  <TableHead>{t('contentRules.col.updated', 'Updated')}</TableHead>
                  <TableHead>{t('contentRules.col.enabled', 'In use')}</TableHead>
                  <TableHead>
                    <span className="sr-only">{t('contentRules.col.actions', 'Actions')}</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => (
                  <TableRow key={r.id} data-testid="content-rule-row">
                    <TableCell>
                      <div className="font-medium break-words">{r.name}</div>
                      <code className="text-xs text-muted-foreground break-all">{r.rule_id}</code>
                    </TableCell>
                    <TableCell>{kindLabel(r.kind)}</TableCell>
                    <TableCell className="text-end">
                      <Badge variant="secondary" className="font-normal tabular-nums">
                        {t('contentRules.versionValue', 'v{version}', { version: r.version })}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <RelativeTime date={r.updated_at} className="text-sm" />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={r.enabled}
                        disabled={!canWrite || toggling === r.id}
                        onCheckedChange={(v) => void toggle(r, v)}
                        aria-label={t('contentRules.toggleNamed', 'Use {name}', { name: r.name })}
                      />
                    </TableCell>
                    <TableCell className="text-end">
                      <div className="flex justify-end gap-2">
                        <GatedButton
                          allowed={canWrite}
                          reason={noWrite}
                          variant="outline"
                          size="sm"
                          onClick={() => setEditing(r)}
                        >
                          {t('contentRules.edit', 'Edit')}
                        </GatedButton>
                        <GatedButton
                          allowed={canWrite}
                          reason={noWrite}
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          aria-label={t('contentRules.deleteNamed', 'Delete {name}', {
                            name: r.name,
                          })}
                          onClick={() => setDeleting(r)}
                        >
                          <Trash2 className="size-4" aria-hidden />
                        </GatedButton>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {canWrite && (
        <ContentRuleDialog
          open={!!editing}
          onOpenChange={(o) => !o && setEditing(null)}
          rule={editing === 'new' ? null : editing}
        />
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('contentRules.deleteTitle', 'Delete the rule "{name}"?', {
          name: deleting?.name ?? '',
        })}
        desc={t(
          'contentRules.deleteDesc',
          'New scan results are no longer matched with it. What it already found stays.'
        )}
        confirmText={t('contentRules.deleteButton', 'Delete rule')}
        destructive
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          deleteContentRule(target.id)
            .then(async () => {
              toast.success(t('contentRules.toast.deleted', 'Rule deleted'))
              await invalidateContentRules()
            })
            .catch((e: unknown) =>
              toast.error(
                getErrorMessage(
                  e,
                  t('contentRules.toast.deleteFailed', 'Could not delete the rule')
                )
              )
            )
        }}
      />
    </PageStack>
  )
}
