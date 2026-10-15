'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { useRouter } from 'next/navigation'
import {
  ArrowLeft,
  Download,
  FlaskConical,
  RefreshCw,
  Save,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  Upload,
  Send,
} from 'lucide-react'
import { Main } from '@/components/layout'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { ErrorState, PageHeader } from '@/features/shared'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { exportToJSON } from '@/lib/utils'
import { cn } from '@/lib/utils'
import {
  invalidateMappings,
  mappingApi,
  useMappingCatalog,
  useMappingProfile,
  useProjectMeta,
} from '../api/use-ticket-mapping-api'
import { exportDocument, normalizeSpec } from '../lib/mapping-utils'
import type { MappingSpec, ValidationIssue } from '../types/ticket-mapping.types'
import { FieldMapper, MappingSettingsBar } from './field-mapper'
import { WorkflowMapper } from './workflow-mapper'
import { MappingPreview } from './mapping-preview'
import { MappingHistory } from './mapping-history'

function IssueList({ issues }: { issues: ValidationIssue[] }) {
  const { t } = useTranslation()
  if (issues.length === 0) {
    return (
      <p className="flex items-center gap-2 text-sm text-success" role="status">
        <ShieldCheck className="h-4 w-4" aria-hidden />
        {t('ticketMapping.editor.noIssues', 'No problems found against the Jira project.')}
      </p>
    )
  }
  return (
    <ul className="grid gap-1 text-sm" aria-label={t('ticketMapping.editor.issues', 'Problems')}>
      {issues.map((i, idx) => (
        <li
          key={idx}
          className={cn(
            'rounded px-2 py-1',
            i.severity === 'error'
              ? 'bg-destructive/10 text-destructive'
              : i.severity === 'warning'
                ? 'bg-warning/10 text-warning'
                : 'bg-muted text-muted-foreground'
          )}
        >
          <span className="me-2 font-medium">
            {t(`ticketMapping.severity.${i.severity}`, i.severity)}
          </span>
          {i.message}
        </li>
      ))}
    </ul>
  )
}

/** The mapping editor of one profile: fields, status, preview, history. Edits
 *  go to the draft; publishing checks the draft against the live Jira project. */
export function MappingEditor({ id }: { id: string }) {
  const { t } = useTranslation()
  const router = useRouter()
  const { can } = usePermissions()
  const canManage = can(Permission.IntegrationsManage)
  const { data: view, error, isLoading, mutate } = useMappingProfile(id)
  const profile = view?.profile
  const { data: catalog } = useMappingCatalog(profile?.object_kind)
  const {
    data: meta,
    isLoading: metaLoading,
    mutate: reloadMeta,
  } = useProjectMeta(
    profile?.integration_id,
    profile?.project_key,
    profile?.issue_type_id,
    profile?.project_id
  )

  const base = view?.draft ?? view?.published
  const [spec, setSpec] = useState<MappingSpec | null>(null)
  const [dirty, setDirty] = useState(false)
  const [issues, setIssues] = useState<ValidationIssue[]>([])
  const [busy, setBusy] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [tab, setTab] = useState('fields')

  useEffect(() => {
    if (base && !dirty) setSpec(normalizeSpec(base.spec))
  }, [base, dirty])

  const verify = useCallback(async () => {
    try {
      const res = await mappingApi.verify(id, 0)
      setIssues(res.issues)
    } catch {
      /* the editor still works without the check */
    }
  }, [id])
  useEffect(() => {
    if (profile) void verify()
  }, [profile, verify])

  const edit = (s: MappingSpec) => {
    setSpec(s)
    setDirty(true)
  }

  const save = async (): Promise<number | null> => {
    if (!spec || !profile) return null
    setBusy(true)
    try {
      const res = await mappingApi.saveDraft(id, spec, profile.draft_version)
      setIssues(res.issues)
      setDirty(false)
      await mutate()
      toast.success(t('ticketMapping.editor.saved', 'Draft v{v} saved', { v: res.version.version }))
      return res.version.version
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('ticketMapping.editor.saveFailed', 'Could not save the draft'))
      )
      return null
    } finally {
      setBusy(false)
    }
  }

  const publish = async () => {
    if (!profile) return
    let draft = profile.draft_version
    if (dirty || draft === 0) {
      const v = await save()
      if (!v) return
      draft = v
    }
    setBusy(true)
    try {
      const res = await mappingApi.publish(id, draft)
      setIssues(res.issues)
      await invalidateMappings(id)
      toast.success(
        t('ticketMapping.editor.published', 'Version {v} published', { v: res.version.version })
      )
    } catch (err) {
      const details = (err as { details?: { issues?: ValidationIssue[] } })?.details
      if (details?.issues) setIssues(details.issues)
      toast.error(
        getErrorMessage(err, t('ticketMapping.editor.publishFailed', 'Could not publish'))
      )
    } finally {
      setBusy(false)
    }
  }

  const discard = async () => {
    setBusy(true)
    try {
      await mappingApi.discardDraft(id)
      setDirty(false)
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('ticketMapping.editor.discardFailed', 'Could not discard the draft'))
      )
    } finally {
      setBusy(false)
    }
  }

  const checkDrift = async () => {
    try {
      const res = await mappingApi.drift(id)
      setIssues(res.issues)
      await mutate()
      toast[res.drifted ? 'warning' : 'success'](
        res.drifted
          ? t('ticketMapping.editor.drifted', 'Jira changed under this mapping: see the problems')
          : t('ticketMapping.editor.noDrift', 'The published mapping still matches Jira')
      )
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('ticketMapping.editor.driftFailed', 'Could not check Jira'))
      )
    }
  }

  const suggest = async () => {
    if (!spec) return
    try {
      const res = await mappingApi.suggest(id)
      if (res.rows.length === 0) {
        toast.info(
          t('ticketMapping.editor.noSuggestions', 'No suggestions for the unmapped fields')
        )
        return
      }
      edit({ ...spec, fields: [...spec.fields, ...res.rows] })
      toast.success(
        t('ticketMapping.editor.suggested', '{n} suggested rows added: review them', {
          n: res.rows.length,
        })
      )
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('ticketMapping.editor.suggestFailed', 'Could not suggest rows'))
      )
    }
  }

  const doImport = async () => {
    if (!profile) return
    setBusy(true)
    try {
      const res = await mappingApi.importDoc(id, importText, profile.draft_version)
      setIssues(res.issues)
      setDirty(false)
      setImportOpen(false)
      setImportText('')
      await mutate()
      toast.success(t('ticketMapping.editor.imported', 'Imported into the draft'))
    } catch (err) {
      toast.error(getErrorMessage(err, t('ticketMapping.editor.importFailed', 'Could not import')))
    } finally {
      setBusy(false)
    }
  }

  const fields = useMemo(() => meta?.fields ?? [], [meta])
  const readOnly = !canManage

  if (isLoading || (!spec && !error)) {
    return (
      <Main>
        <Skeleton className="h-10 w-80" />
        <Skeleton className="mt-6 h-96 w-full" />
      </Main>
    )
  }
  if (error || !profile || !spec) {
    return (
      <Main>
        <ErrorState
          title={t('ticketMapping.list.title', 'Ticket field mapping')}
          error={error}
          onRetry={() => mutate()}
        />
      </Main>
    )
  }

  const errorCount = issues.filter((i) => i.severity === 'error').length

  return (
    <Main>
      <Link
        href="/settings/integrations/ticketing/mappings"
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        {t('ticketMapping.list.title', 'Ticket field mapping')}
      </Link>
      <PageHeader
        title={profile.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <span>
              {profile.project_key} · {profile.issue_type || profile.issue_type_id} ·{' '}
              {profile.object_kind === 'task'
                ? t('ticketMapping.kind.taskShort', 'Tasks')
                : t('ticketMapping.kind.findingShort', 'Findings')}
            </span>
            {profile.published_version > 0 ? (
              <Badge variant="outline">
                {t('ticketMapping.list.published', 'Published v{v}', {
                  v: profile.published_version,
                })}
              </Badge>
            ) : (
              <Badge variant="outline">
                {t('ticketMapping.list.notPublished', 'Not published')}
              </Badge>
            )}
            {profile.draft_version > 0 && (
              <Badge variant="secondary">
                {t('ticketMapping.list.draft', 'Draft v{v}', { v: profile.draft_version })}
              </Badge>
            )}
            {dirty && (
              <Badge variant="secondary">
                {t('ticketMapping.editor.unsaved', 'Unsaved changes')}
              </Badge>
            )}
          </span>
        }
      >
        {canManage && (
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={save} disabled={busy || !dirty}>
              <Save className="me-1 h-4 w-4" aria-hidden />
              {t('ticketMapping.editor.save', 'Save draft')}
            </Button>
            <Button onClick={publish} disabled={busy || errorCount > 0}>
              <Send className="me-1 h-4 w-4" aria-hidden />
              {t('ticketMapping.editor.publish', 'Publish')}
            </Button>
          </div>
        )}
      </PageHeader>

      {profile.drifted && (
        <div
          className="mt-4 flex flex-wrap items-center gap-2 rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm"
          role="alert"
        >
          <TriangleAlert className="h-4 w-4 text-destructive" aria-hidden />
          {t(
            'ticketMapping.editor.driftBanner',
            'Jira changed under the published mapping (a field or status it uses). Fix the mapping and publish again.'
          )}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button variant="ghost" size="sm" onClick={() => reloadMeta()} disabled={metaLoading}>
          <RefreshCw className={cn('me-1 h-4 w-4', metaLoading && 'animate-spin')} aria-hidden />
          {t('ticketMapping.editor.reloadJira', 'Reload from Jira')}
        </Button>
        <Button variant="ghost" size="sm" onClick={verify}>
          <ShieldCheck className="me-1 h-4 w-4" aria-hidden />
          {t('ticketMapping.editor.verify', 'Check')}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={checkDrift}
          disabled={!canManage || profile.published_version === 0}
        >
          <TriangleAlert className="me-1 h-4 w-4" aria-hidden />
          {t('ticketMapping.editor.drift', 'Check for Jira changes')}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() =>
            exportToJSON(
              exportDocument(spec, profile.object_kind, profile.project_key, profile.issue_type),
              `ticket-mapping-${profile.project_key}-${profile.object_kind}`
            )
          }
        >
          <Download className="me-1 h-4 w-4" aria-hidden />
          {t('ticketMapping.editor.export', 'Export')}
        </Button>
        {canManage && (
          <>
            <Button variant="ghost" size="sm" onClick={() => setImportOpen(true)}>
              <Upload className="me-1 h-4 w-4" aria-hidden />
              {t('ticketMapping.editor.import', 'Import')}
            </Button>
            {profile.draft_version > 0 && (
              <Button variant="ghost" size="sm" onClick={discard} disabled={busy}>
                {t('ticketMapping.editor.discard', 'Discard draft')}
              </Button>
            )}
            <label className="ms-2 flex items-center gap-2 text-sm">
              <FlaskConical className="h-4 w-4 text-muted-foreground" aria-hidden />
              <Switch
                checked={profile.dry_run}
                onCheckedChange={async (v) => {
                  try {
                    await mappingApi.setDryRun(id, v)
                    await mutate()
                  } catch (err) {
                    toast.error(
                      getErrorMessage(
                        err,
                        t('ticketMapping.editor.dryRunFailed', 'Could not change dry run')
                      )
                    )
                  }
                }}
              />
              {t('ticketMapping.editor.dryRun', 'Dry run (log only)')}
            </label>
            <Button
              variant="ghost"
              size="sm"
              className="text-destructive"
              onClick={() => setDeleteOpen(true)}
            >
              <Trash2 className="me-1 h-4 w-4" aria-hidden />
              {t('ticketMapping.editor.delete', 'Delete')}
            </Button>
          </>
        )}
      </div>

      <div className="mt-4">
        <IssueList issues={issues} />
      </div>

      {!catalog ? (
        <Skeleton className="mt-6 h-96 w-full" />
      ) : (
        <Tabs value={tab} onValueChange={setTab} className="mt-6 min-w-0">
          <TabsList>
            <TabsTrigger value="fields">{t('ticketMapping.tab.fields', 'Fields')}</TabsTrigger>
            <TabsTrigger value="status">{t('ticketMapping.tab.status', 'Status')}</TabsTrigger>
            <TabsTrigger value="preview">{t('ticketMapping.tab.preview', 'Preview')}</TabsTrigger>
            <TabsTrigger value="history">{t('ticketMapping.tab.history', 'History')}</TabsTrigger>
          </TabsList>
          <TabsContent value="fields" className="mt-4 grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4">
            <MappingSettingsBar spec={spec} onChange={edit} readOnly={readOnly} />
            {metaLoading && fields.length === 0 ? (
              <Skeleton className="h-80 w-full" />
            ) : (
              <FieldMapper
                spec={spec}
                onChange={edit}
                catalog={catalog}
                fields={fields}
                issues={issues}
                readOnly={readOnly}
                onSuggest={canManage ? suggest : undefined}
              />
            )}
          </TabsContent>
          <TabsContent value="status" className="mt-4 min-w-0">
            <WorkflowMapper
              profileId={id}
              kind={profile.object_kind}
              spec={spec}
              onChange={edit}
              catalog={catalog}
              workflow={meta?.workflow}
              issues={issues}
              readOnly={readOnly}
              dirty={dirty}
            />
          </TabsContent>
          <TabsContent value="preview" className="mt-4 min-w-0">
            <MappingPreview
              profileId={id}
              kind={profile.object_kind}
              fields={fields}
              dirty={dirty}
            />
          </TabsContent>
          <TabsContent value="history" className="mt-4">
            <MappingHistory
              profileId={id}
              onRolledBack={() => {
                setDirty(false)
                void mutate()
                setTab('fields')
              }}
            />
          </TabsContent>
        </Tabs>
      )}

      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('ticketMapping.import.title', 'Import a mapping')}</DialogTitle>
            <DialogDescription>
              {t(
                'ticketMapping.import.description',
                'Paste an exported JSON or YAML document. It replaces the draft; nothing is published.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <input
              type="file"
              accept=".json,.yaml,.yml,application/json,application/yaml"
              aria-label={t('ticketMapping.import.file', 'File')}
              className="text-sm"
              onChange={async (e) => {
                const f = e.target.files?.[0]
                if (f && f.size <= 256 * 1024) setImportText(await f.text())
                else if (f)
                  toast.error(t('ticketMapping.import.tooLarge', 'The file is larger than 256 KiB'))
              }}
            />
            <Textarea
              rows={14}
              className="mt-3 font-mono text-xs"
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              aria-label={t('ticketMapping.import.document', 'Document')}
            />
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              {t('ticketMapping.common.cancel', 'Cancel')}
            </Button>
            <Button onClick={doImport} disabled={busy || !importText.trim()}>
              {t('ticketMapping.import.submit', 'Import into the draft')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t('ticketMapping.delete.title', 'Delete this mapping?')}
        desc={t(
          'ticketMapping.delete.description',
          'Tickets for this destination go back to the built-in fields. Versions are deleted; the audit log keeps the history.'
        )}
        confirmText={t('ticketMapping.editor.delete', 'Delete')}
        destructive
        handleConfirm={async () => {
          try {
            await mappingApi.remove(id)
            await invalidateMappings()
            router.push('/settings/integrations/ticketing/mappings')
          } catch (err) {
            toast.error(
              getErrorMessage(err, t('ticketMapping.delete.failed', 'Could not delete the mapping'))
            )
          }
        }}
      />
    </Main>
  )
}
