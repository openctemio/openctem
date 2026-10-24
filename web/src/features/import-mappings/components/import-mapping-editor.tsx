'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { ArrowLeft, CheckCircle2, FileCode2, Pencil, Save, ShieldCheck, Trash2 } from 'lucide-react'
import { Main } from '@/components/layout'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { confirmName } from '@/lib/confirm-name'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  identityChangeOf,
  importMappingsApi,
  invalidateImportMappings,
  useImportMapping,
  useImportMappingTemplates,
  validationErrorsOf,
  type IdentityChange,
} from '../api/import-mappings-api'
import {
  blankDocument,
  documentFromDraft,
  draftFromDocument,
  draftProblems,
  type DraftProblem,
  type MappingDraft,
} from '../lib/mapping-model'
import {
  MAPPING_SOURCES,
  type MappingDocument,
  type ValidateResult,
} from '../types/import-mapping.types'
import { IMPORT_MAPPINGS_PATH } from '../lib/paths'
import { MappingTable } from './mapping-table'
import { PreviewPane } from './preview-pane'
import { SamplePane } from './sample-pane'
import {
  CreateMappingDialog,
  EditDetailsDialog,
  IdentityConfirmDialog,
  SaveVersionDialog,
} from './save-dialogs'
import { VersionHistory } from './version-history'

type Translate = ReturnType<typeof useTranslation>['t']

function problemText(t: Translate, p: DraftProblem): string {
  switch (p.code) {
    case 'no_rules':
      return t('importMappings.problem.noRules', 'Add at least one rule.')
    case 'missing_target':
      return t('importMappings.problem.missingTarget', 'Rule {rule}: pick a field for every row.', {
        rule: p.rule,
      })
    case 'required':
      return t('importMappings.problem.required', 'Rule {rule}: {target} is required.', {
        rule: p.rule,
        target: p.target,
      })
    case 'duplicate':
      return t('importMappings.problem.duplicate', 'Rule {rule}: {target} is set twice.', {
        rule: p.rule,
        target: p.target,
      })
    case 'identity_required':
      return t(
        'importMappings.problem.identityRequired',
        'Tick Identity on at least one field: it tells one finding from another.'
      )
    case 'identity_too_many':
      return t('importMappings.problem.identityTooMany', 'At most 8 identity fields.')
    case 'identity_unset':
      return t(
        'importMappings.problem.identityUnset',
        'Rule {rule}: the identity field {target} must be set by every finding rule.',
        { rule: p.rule, target: p.target }
      )
    case 'each_required':
      return t('importMappings.problem.eachRequired', 'XML needs the record elements.')
  }
}

/** A parsed Advanced JSON text, if it is shaped like a mapping document. */
export function parseDocumentText(text: string): MappingDocument | null {
  let v: unknown
  try {
    v = JSON.parse(text)
  } catch {
    return null
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null
  const o = v as Record<string, unknown>
  if (!Array.isArray(o.records)) return null
  if (typeof o.source !== 'string' || !(MAPPING_SOURCES as string[]).includes(o.source)) return null
  const rulesOk = o.records.every(
    (r) =>
      r &&
      typeof r === 'object' &&
      typeof (r as Record<string, unknown>).kind === 'string' &&
      (r as Record<string, unknown>).set !== null &&
      typeof (r as Record<string, unknown>).set === 'object'
  )
  return rulesOk ? (v as MappingDocument) : null
}

function TemplatePicker({ onPick }: { onPick: (doc: MappingDocument, name: string) => void }) {
  const { t } = useTranslation()
  const { data, isLoading } = useImportMappingTemplates()
  const templates = data?.items ?? []
  return (
    <section className="mt-6" aria-labelledby="im-start">
      <h2 id="im-start" className="text-base font-semibold">
        {t('importMappings.start.title', 'Start from')}
      </h2>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {isLoading && [0, 1, 2].map((i) => <Skeleton key={i} className="h-28 w-full" />)}
        {templates.map((tpl) => (
          <button
            key={tpl.key}
            type="button"
            className="flex min-w-0 flex-col items-start gap-1 rounded-lg border bg-card p-4 text-start hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onClick={() => onPick(tpl.mapping, tpl.key)}
          >
            <span className="flex w-full items-center justify-between gap-2">
              <span className="font-medium">{tpl.name}</span>
              <Badge variant="outline">
                {t(`importMappings.source.${tpl.source}`, tpl.source.toUpperCase())}
              </Badge>
            </span>
            <span className="text-sm text-muted-foreground">{tpl.description}</span>
          </button>
        ))}
        <button
          type="button"
          className="flex min-w-0 flex-col items-start gap-1 rounded-lg border border-dashed bg-card p-4 text-start hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onClick={() => onPick(blankDocument(), '')}
        >
          <span className="font-medium">{t('importMappings.start.blank', 'Blank mapping')}</span>
          <span className="text-sm text-muted-foreground">
            {t(
              'importMappings.start.blankHelp',
              'One finding per CSV row from title and severity columns; build the rest from your sample.'
            )}
          </span>
        </button>
      </div>
    </section>
  )
}

/** The mapping editor: sample, field table and live preview; create or save versions. */
export function ImportMappingEditor({ id }: { id?: string }) {
  const { t } = useTranslation()
  const router = useRouter()
  const { can } = usePermissions()
  const canManage = can(Permission.IntegrationsManage)
  const readOnly = !canManage
  const isNew = !id

  const { data: detail, error, isLoading, mutate } = useImportMapping(id)
  const [draft, setDraft] = useState<MappingDraft | null>(null)
  const [baseline, setBaseline] = useState('')
  const [syncedVersion, setSyncedVersion] = useState<number | null>(null)
  const [suggestedName, setSuggestedName] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [fields, setFields] = useState<string[]>([])
  const [advanced, setAdvanced] = useState(false)
  const [jsonText, setJsonText] = useState('')
  const [jsonError, setJsonError] = useState(false)
  const [tab, setTab] = useState('mapping')

  const [createOpen, setCreateOpen] = useState(false)
  const [versionOpen, setVersionOpen] = useState(false)
  const [detailsOpen, setDetailsOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [pendingIdentity, setPendingIdentity] = useState<{
    note: string
    change: IdentityChange
  } | null>(null)
  const [busy, setBusy] = useState(false)
  const [saveErrors, setSaveErrors] = useState<string[]>([])
  const [validation, setValidation] = useState<ValidateResult | null>(null)

  const loadDocument = useCallback((doc: MappingDocument, markClean: boolean) => {
    const d = draftFromDocument(doc)
    setDraft(d)
    if (markClean) setBaseline(JSON.stringify(documentFromDraft(d)))
    setJsonText(JSON.stringify(documentFromDraft(d), null, 2))
    setJsonError(false)
    setValidation(null)
  }, [])

  // Load the latest version on first load and after each save.
  const latest = detail?.version
  useEffect(() => {
    if (latest && latest.version !== syncedVersion) {
      setSyncedVersion(latest.version)
      loadDocument(latest.mapping, true)
    }
  }, [latest, syncedVersion, loadDocument])

  const doc = useMemo(() => (draft ? documentFromDraft(draft) : null), [draft])
  const docJson = doc ? JSON.stringify(doc) : ''
  const dirty = isNew ? draft !== null : docJson !== baseline
  const problems = useMemo(() => (draft ? draftProblems(draft) : []), [draft])

  const editDraft = useCallback((next: MappingDraft) => {
    setDraft(next)
    setJsonText(JSON.stringify(documentFromDraft(next), null, 2))
    setJsonError(false)
    setValidation(null)
  }, [])

  const editJson = (text: string) => {
    setJsonText(text)
    const parsed = parseDocumentText(text)
    if (parsed) {
      setDraft(draftFromDocument(parsed))
      setJsonError(false)
      setValidation(null)
    } else {
      setJsonError(true)
    }
  }

  const create = async (input: { name: string; description: string; note: string }) => {
    if (!doc) return
    setBusy(true)
    setSaveErrors([])
    try {
      const res = await importMappingsApi.create({
        name: input.name,
        description: input.description || undefined,
        mapping: doc,
        note: input.note || undefined,
      })
      toast.success(t('importMappings.create.saved', 'Mapping saved'))
      await invalidateImportMappings()
      setCreateOpen(false)
      router.replace(`${IMPORT_MAPPINGS_PATH}/${res.mapping.id}`)
    } catch (err) {
      setSaveErrors(validationErrorsOf(err))
      toast.error(
        getErrorMessage(err, t('importMappings.create.failed', 'Could not save the mapping'))
      )
    } finally {
      setBusy(false)
    }
  }

  const saveVersion = async (note: string, confirmIdentity = false) => {
    if (!doc || !id) return
    setBusy(true)
    setSaveErrors([])
    try {
      await importMappingsApi.createVersion(id, {
        mapping: doc,
        note: note || undefined,
        ...(confirmIdentity ? { confirm_identity_change: true } : {}),
      })
      toast.success(t('importMappings.save.saved', 'New version saved'))
      setVersionOpen(false)
      setPendingIdentity(null)
      await invalidateImportMappings()
      await mutate()
    } catch (err) {
      const change = identityChangeOf(err)
      if (change && !confirmIdentity) {
        setVersionOpen(false)
        setPendingIdentity({ note, change })
        return
      }
      setSaveErrors(validationErrorsOf(err))
      if (pendingIdentity) setPendingIdentity(null)
      if (!versionOpen) setVersionOpen(true)
      toast.error(
        getErrorMessage(err, t('importMappings.save.failed', 'Could not save the version'))
      )
    } finally {
      setBusy(false)
    }
  }

  const validate = async () => {
    if (!doc) return
    try {
      setValidation(await importMappingsApi.validate(doc))
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('importMappings.validate.failed', 'Could not check the mapping'))
      )
    }
  }

  const updateDetails = async (input: { name?: string; description?: string }) => {
    if (!id) return
    setBusy(true)
    try {
      await importMappingsApi.update(id, input)
      toast.success(t('importMappings.details.saved', 'Saved'))
      setDetailsOpen(false)
      await invalidateImportMappings()
    } catch (err) {
      toast.error(getErrorMessage(err, t('importMappings.details.failed', 'Could not save')))
    } finally {
      setBusy(false)
    }
  }

  // ---- states before the editor --------------------------------------------
  if (!isNew && isLoading) {
    return (
      <Main>
        <PageStack>
          <Skeleton className="h-10 w-72" />
          <Skeleton className="h-96 w-full" />
        </PageStack>
      </Main>
    )
  }
  if (!isNew && (error || !detail)) {
    return (
      <Main>
        <PageStack>
          <ErrorState
            title={t('importMappings.editor.loadFailed', 'Could not load the mapping')}
            error={error}
            onRetry={() => mutate()}
          />
        </PageStack>
      </Main>
    )
  }

  const mapping = detail?.mapping
  const title = mapping ? mapping.name : t('importMappings.editor.newTitle', 'New import mapping')

  return (
    <Main>
      <PageStack>
        <Link
          href="/settings/integrations/import-mappings"
          className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          {t('importMappings.editor.back', 'Import mappings')}
        </Link>
        <PageHeader
          title={title}
          description={
            mapping ? (
              <>
                {mapping.description && <span className="block">{mapping.description}</span>}
                <span className="block">
                  {t('importMappings.editor.usage', 'Imports choose it as format {format}.', {
                    format: `mapping:${mapping.name}`,
                  })}
                </span>
              </>
            ) : (
              t(
                'importMappings.editor.newDescription',
                'Map the columns of a CSV, JSON, JSON Lines or XML export to findings and assets, checking the result on a sample.'
              )
            )
          }
        >
          {draft && (
            <div className="flex flex-wrap items-center gap-2">
              <Can permission={Permission.IntegrationsManage}>
                <Button variant="outline" onClick={validate}>
                  <ShieldCheck className="me-1 h-4 w-4" aria-hidden />
                  {t('importMappings.editor.validate', 'Check')}
                </Button>
                {isNew ? (
                  <Button
                    onClick={() => {
                      setSaveErrors([])
                      setCreateOpen(true)
                    }}
                    disabled={busy}
                  >
                    <Save className="me-1 h-4 w-4" aria-hidden />
                    {t('importMappings.editor.save', 'Save')}
                  </Button>
                ) : (
                  <Button
                    onClick={() => {
                      setSaveErrors([])
                      setVersionOpen(true)
                    }}
                    disabled={busy || !dirty}
                  >
                    <Save className="me-1 h-4 w-4" aria-hidden />
                    {t('importMappings.editor.saveVersion', 'Save as new version')}
                  </Button>
                )}
              </Can>
            </div>
          )}
        </PageHeader>

        {mapping && (
          <Can permission={Permission.IntegrationsManage}>
            <div className="flex flex-wrap gap-2">
              <Button variant="ghost" size="sm" onClick={() => setDetailsOpen(true)}>
                <Pencil className="me-1 h-4 w-4" aria-hidden />
                {t('importMappings.editor.editDetails', 'Rename')}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="ms-4 text-destructive hover:text-destructive"
                onClick={() => setDeleteOpen(true)}
              >
                <Trash2 className="me-1 h-4 w-4" aria-hidden />
                {t('importMappings.editor.delete', 'Delete')}
              </Button>
            </div>
          </Can>
        )}

        {isNew && !canManage ? (
          <p className="mt-6 text-sm text-muted-foreground">
            {t(
              'importMappings.editor.noPermission',
              'Creating a mapping needs the permission to manage integrations.'
            )}
          </p>
        ) : isNew && !draft ? (
          <TemplatePicker
            onPick={(d, name) => {
              loadDocument(d, false)
              setSuggestedName(name)
            }}
          />
        ) : draft && doc ? (
          <>
            {(problems.length > 0 || validation) && (
              <div className="grid gap-2">
                {problems.length > 0 && (
                  <ul
                    className="grid gap-1 rounded-md border p-3 text-sm"
                    aria-label={t('importMappings.problem.label', 'To fix')}
                  >
                    {problems.map((p, i) => (
                      <li key={i}>{problemText(t, p)}</li>
                    ))}
                  </ul>
                )}
                {validation &&
                  (validation.valid ? (
                    <p className="flex items-center gap-2 text-sm" role="status">
                      <CheckCircle2 className="h-4 w-4 text-success" aria-hidden />
                      {t(
                        'importMappings.validate.ok',
                        'The mapping is valid. Identity: {members}.',
                        {
                          members: validation.identity.join(', ') || '-',
                        }
                      )}
                    </p>
                  ) : (
                    <ul
                      className="list-disc rounded-md border border-destructive/50 bg-destructive/5 p-3 ps-7 text-sm"
                      role="alert"
                    >
                      {validation.errors.map((e, i) => (
                        <li key={i} className="break-words">
                          {e}
                        </li>
                      ))}
                    </ul>
                  ))}
              </div>
            )}

            <Tabs value={tab} onValueChange={setTab} className="min-w-0">
              {!isNew && (
                <TabsList>
                  <TabsTrigger value="mapping">
                    {t('importMappings.tab.mapping', 'Mapping')}
                  </TabsTrigger>
                  <TabsTrigger value="versions">
                    {t('importMappings.tab.versions', 'Versions')}
                    <TabsCount value={detail?.versions.length} />
                  </TabsTrigger>
                </TabsList>
              )}
              <TabsContent value="mapping" className="min-w-0">
                <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-[16rem_minmax(0,1fr)] 2xl:grid-cols-[16rem_minmax(0,1fr)_minmax(0,26rem)]">
                  <section
                    className="min-w-0 self-start rounded-lg border bg-card p-4"
                    aria-labelledby="im-pane-sample"
                  >
                    <h2 id="im-pane-sample" className="mb-3 text-sm font-semibold">
                      {t('importMappings.pane.sample', 'Sample')}
                    </h2>
                    <SamplePane
                      draft={draft}
                      onChange={editDraft}
                      file={file}
                      onFile={(f) => {
                        setFile(f)
                        if (!f) setFields([])
                      }}
                      autoSource={isNew}
                      readOnly={readOnly}
                    />
                  </section>

                  <section className="min-w-0" aria-labelledby="im-pane-fields">
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                      <h2 id="im-pane-fields" className="text-sm font-semibold">
                        {t('importMappings.pane.fields', 'Fields')}
                      </h2>
                      <label className="flex items-center gap-2 text-sm">
                        <FileCode2 className="h-4 w-4 text-muted-foreground" aria-hidden />
                        {t('importMappings.editor.advanced', 'Advanced: JSON')}
                        <Switch
                          checked={advanced}
                          onCheckedChange={(v) => {
                            if (v) setJsonText(JSON.stringify(doc, null, 2))
                            setAdvanced(v)
                          }}
                        />
                      </label>
                    </div>
                    {advanced ? (
                      <div className="grid gap-2">
                        <Textarea
                          rows={24}
                          spellCheck={false}
                          className="font-mono text-xs"
                          value={jsonText}
                          readOnly={readOnly}
                          aria-invalid={jsonError}
                          aria-label={t(
                            'importMappings.editor.jsonLabel',
                            'Mapping document (JSON)'
                          )}
                          onChange={(e) => editJson(e.target.value)}
                        />
                        {jsonError && (
                          <p className="text-sm text-destructive" role="alert">
                            {t(
                              'importMappings.editor.jsonInvalid',
                              'Not a mapping document yet: it needs valid JSON with source and records. The table keeps the last valid version.'
                            )}
                          </p>
                        )}
                      </div>
                    ) : (
                      <MappingTable
                        draft={draft}
                        onChange={editDraft}
                        fields={fields}
                        readOnly={readOnly}
                      />
                    )}
                  </section>

                  <section
                    className="min-w-0 self-start rounded-lg border bg-card p-4 lg:col-span-2 2xl:col-span-1"
                    aria-labelledby="im-pane-preview"
                  >
                    <h2 id="im-pane-preview" className="mb-3 text-sm font-semibold">
                      {t('importMappings.pane.preview', 'Preview')}
                    </h2>
                    <PreviewPane
                      document={doc}
                      file={file}
                      canPreview={canManage}
                      onFields={setFields}
                    />
                  </section>
                </div>
              </TabsContent>
              {!isNew && detail && id && (
                <TabsContent value="versions">
                  <VersionHistory
                    mappingId={id}
                    versions={detail.versions}
                    latest={detail.mapping.latest_version}
                    onLoad={
                      canManage
                        ? (d) => {
                            loadDocument(d, false)
                            setTab('mapping')
                          }
                        : undefined
                    }
                  />
                </TabsContent>
              )}
            </Tabs>
          </>
        ) : null}

        <CreateMappingDialog
          open={createOpen}
          onOpenChange={setCreateOpen}
          onSubmit={create}
          busy={busy}
          errors={saveErrors}
          initialName={suggestedName}
        />
        <SaveVersionDialog
          open={versionOpen}
          onOpenChange={setVersionOpen}
          onSubmit={(note) => saveVersion(note)}
          busy={busy}
          errors={saveErrors}
          nextVersion={(mapping?.latest_version ?? 0) + 1}
        />
        <IdentityConfirmDialog
          change={pendingIdentity?.change ?? null}
          busy={busy}
          onCancel={() => setPendingIdentity(null)}
          onConfirm={() => pendingIdentity && saveVersion(pendingIdentity.note, true)}
        />
        {mapping && (
          <>
            <EditDetailsDialog
              open={detailsOpen}
              onOpenChange={setDetailsOpen}
              name={mapping.name}
              description={mapping.description}
              onSubmit={updateDetails}
              busy={busy}
            />
            <ConfirmDialog
              open={deleteOpen}
              onOpenChange={setDeleteOpen}
              title={t('confirm.importMapping.deleteTitle', undefined, { name: mapping.name })}
              desc={t('confirm.importMapping.deleteDesc')}
              confirmText={t('confirm.importMapping.deleteBtn')}
              destructive
              typeToConfirm={confirmName(mapping.name, mapping.id)}
              handleConfirm={async () => {
                if (!id) return
                try {
                  await importMappingsApi.remove(id)
                  await invalidateImportMappings()
                  router.push(IMPORT_MAPPINGS_PATH)
                } catch (err) {
                  toast.error(
                    getErrorMessage(
                      err,
                      t('importMappings.delete.failed', 'Could not delete the mapping')
                    )
                  )
                }
              }}
            />
          </>
        )}
      </PageStack>
    </Main>
  )
}
