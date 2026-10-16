'use client'

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { useRouter } from 'next/navigation'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  useIntegrationsApi,
  useJiraProjectsApi,
} from '@/features/integrations/api/use-integrations-api'
import {
  invalidateMappings,
  mappingApi,
  useIssueTypes,
  useMappingCatalog,
} from '../api/use-ticket-mapping-api'
import type { ObjectKind } from '../types/ticket-mapping.types'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** Creates a mapping profile for one destination: site, project, issue type,
 *  object kind, and an optional preset to start from. */
export function CreateMappingDialog({ open, onOpenChange }: Props) {
  const { t } = useTranslation()
  const router = useRouter()
  const [integrationId, setIntegrationId] = useState('')
  const [kind, setKind] = useState<ObjectKind>('finding')
  const [projectKey, setProjectKey] = useState('')
  const [issueTypeId, setIssueTypeId] = useState('')
  const [preset, setPreset] = useState('')
  const [saving, setSaving] = useState(false)

  const { data: integrations } = useIntegrationsApi(
    open ? { category: 'ticketing', provider: 'jira', per_page: 50 } : undefined
  )
  const sites = useMemo(
    () =>
      (integrations?.data ?? []).filter((i) => i.provider === 'jira' && i.status === 'connected'),
    [integrations]
  )
  const site = integrationId || sites[0]?.id || ''
  const { data: projectsData } = useJiraProjectsApi(open)
  const projects = projectsData?.projects ?? []
  const { data: typesData, isLoading: typesLoading } = useIssueTypes(
    site || undefined,
    projectKey || undefined
  )
  const issueTypes = (typesData?.issue_types ?? []).filter((it) => !it.subtask)
  const { data: catalog } = useMappingCatalog(open ? kind : undefined)
  const issueType = issueTypes.find((it) => it.id === issueTypeId)

  const reset = () => {
    setProjectKey('')
    setIssueTypeId('')
    setPreset('')
  }

  const submit = async () => {
    if (!site || !projectKey || !issueTypeId) return
    setSaving(true)
    try {
      const res = await mappingApi.create({
        integration_id: site,
        object_kind: kind,
        project_key: projectKey.trim().toUpperCase(),
        project_id: projects.find((p) => p.key === projectKey)?.id,
        issue_type_id: issueTypeId,
        issue_type: issueType?.name,
        preset: preset || undefined,
      })
      await invalidateMappings()
      toast.success(t('ticketMapping.create.created', 'Mapping created as a draft'))
      onOpenChange(false)
      reset()
      router.push(`/settings/integrations/ticketing/mappings/${res.mapping.profile.id}`)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('ticketMapping.create.failed', 'Could not create the mapping'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('ticketMapping.create.title', 'New field mapping')}</DialogTitle>
          <DialogDescription>
            {t(
              'ticketMapping.create.description',
              'One mapping per destination: a Jira site, a project, an issue type, and findings or remediation tasks.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {sites.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t('ticketMapping.create.noSite', 'Connect a Jira site under Ticketing first.')}
            </p>
          ) : (
            <div className="grid gap-4">
              {sites.length > 1 && (
                <div className="grid gap-2">
                  <Label htmlFor="tm-site">{t('ticketMapping.create.site', 'Jira site')}</Label>
                  <Select
                    value={site}
                    onValueChange={(v) => {
                      setIntegrationId(v)
                      reset()
                    }}
                  >
                    <SelectTrigger id="tm-site">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {sites.map((s) => (
                        <SelectItem key={s.id} value={s.id}>
                          {s.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
              <div className="grid gap-2">
                <Label htmlFor="tm-kind">{t('ticketMapping.create.kind', 'Maps')}</Label>
                <Select
                  value={kind}
                  onValueChange={(v) => {
                    setKind(v as ObjectKind)
                    setPreset('')
                  }}
                >
                  <SelectTrigger id="tm-kind">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="finding">
                      {t('ticketMapping.kind.finding', 'Findings (one issue per finding)')}
                    </SelectItem>
                    <SelectItem value="task">
                      {t('ticketMapping.kind.task', 'Remediation tasks (one issue per task)')}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="tm-project">{t('ticketMapping.create.project', 'Project')}</Label>
                {projects.length > 0 ? (
                  <Select
                    value={projectKey}
                    onValueChange={(v) => {
                      setProjectKey(v)
                      setIssueTypeId('')
                    }}
                  >
                    <SelectTrigger id="tm-project">
                      <SelectValue
                        placeholder={t('ticketMapping.create.pickProject', 'Pick a project')}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {projects.map((p) => (
                        <SelectItem key={p.key} value={p.key}>
                          {p.key} · {p.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    id="tm-project"
                    value={projectKey}
                    maxLength={32}
                    placeholder="SEC"
                    onChange={(e) => {
                      setProjectKey(e.target.value.toUpperCase())
                      setIssueTypeId('')
                    }}
                  />
                )}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="tm-type">{t('ticketMapping.create.issueType', 'Issue type')}</Label>
                <Select
                  value={issueTypeId}
                  onValueChange={setIssueTypeId}
                  disabled={!projectKey || typesLoading}
                >
                  <SelectTrigger id="tm-type">
                    <SelectValue
                      placeholder={
                        typesLoading
                          ? t('ticketMapping.common.loading', 'Loading…')
                          : t('ticketMapping.create.pickType', 'Pick an issue type')
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {issueTypes.map((it) => (
                      <SelectItem key={it.id} value={it.id}>
                        {it.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="tm-preset">{t('ticketMapping.create.preset', 'Start from')}</Label>
                <Select
                  value={preset || 'none'}
                  onValueChange={(v) => setPreset(v === 'none' ? '' : v)}
                >
                  <SelectTrigger id="tm-preset">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">
                      {t('ticketMapping.create.empty', 'An empty mapping')}
                    </SelectItem>
                    {(catalog?.presets ?? []).map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {t(`ticketMapping.preset.${p.id}`, p.id)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {preset && (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      `ticketMapping.presetDesc.${preset}`,
                      catalog?.presets.find((p) => p.id === preset)?.description ?? ''
                    )}
                  </p>
                )}
              </div>
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('ticketMapping.common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={saving || !site || !projectKey || !issueTypeId}>
            {saving
              ? t('ticketMapping.common.saving', 'Saving…')
              : t('ticketMapping.create.submit', 'Create draft')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
