'use client'

import { useMemo } from 'react'
import { TriangleAlert, ArrowLeftRight, Sparkles } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import {
  useIssueTypes,
  useMappingProfiles,
} from '@/features/ticket-mapping/api/use-ticket-mapping-api'
import type { IssueTypeRef } from '@/features/ticket-mapping/types/ticket-mapping.types'
import {
  ISSUE_KINDS,
  STOCK_ISSUE_TYPES,
  suggestIssueType,
  type IssueKind,
  type IssueTypeChoices,
  type TicketingHealth,
} from '../lib/issue-types'

const NONE = '__stock__'

interface Props {
  integrationId: string
  /** The integration's default project (issue types are listed for it). */
  projectKey: string
  value: IssueTypeChoices
  onChange: (next: IssueTypeChoices) => void
  /** metadata.ticketing_health: create refusals per kind. */
  health?: TicketingHealth
}

/**
 * One row per kind of issue (finding, remediation task, campaign epic): the
 * Jira issue type, chosen from the default project's live list (stored by id
 * and name), whether a field mapping fills the type's fields and statuses,
 * and the last create refusal for that kind.
 */
export function IssueTypeMapping({ integrationId, projectKey, value, onChange, health }: Props) {
  const { t } = useTranslation()
  const project = projectKey.trim().toUpperCase()
  const { data, isLoading, error } = useIssueTypes(integrationId, project || undefined)
  const types = useMemo(() => (data?.issue_types ?? []).filter((it) => !it.subtask), [data])
  const { data: profilesData } = useMappingProfiles()
  const profiles = (profilesData?.data ?? []).filter((p) => p.integration_id === integrationId)

  const kindLabel: Record<IssueKind, string> = {
    finding: t('ticketingIntegration.issueTypes.kind.finding', 'Findings'),
    task: t('ticketingIntegration.issueTypes.kind.task', 'Remediation tasks'),
    epic: t('ticketingIntegration.issueTypes.kind.epic', 'Campaigns (epic)'),
  }

  const set = (kind: IssueKind, it: IssueTypeRef | undefined) => {
    const next = { ...value }
    if (it) next[kind] = { id: it.id, name: it.name }
    else delete next[kind]
    onChange(next)
  }

  if (!project) {
    return (
      <p className="text-muted-foreground text-xs">
        {t(
          'ticketingIntegration.issueTypes.needProject',
          'Choose a default project first: issue types are chosen from its list.'
        )}
      </p>
    )
  }

  return (
    <div className="space-y-3">
      {error && (
        <p className="text-destructive text-xs">
          {t(
            'ticketingIntegration.issueTypes.loadFailed',
            'The issue types of this project could not be read from Jira.'
          )}
        </p>
      )}
      {ISSUE_KINDS.map((kind) => {
        const chosen = value[kind]
        const known = chosen?.id ? types.find((it) => it.id === chosen.id) : undefined
        const suggestion = !chosen ? suggestIssueType(kind, types) : undefined
        const profile =
          kind !== 'epic' && chosen?.id
            ? profiles.find(
                (p) =>
                  p.object_kind === kind &&
                  p.project_key === project &&
                  p.issue_type_id === chosen.id
              )
            : undefined
        const problem = health?.[kind]
        const selectId = `issue-type-${kind}`
        return (
          <div key={kind} className="space-y-1.5 rounded-md border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Label htmlFor={selectId} className="text-xs font-medium">
                {kindLabel[kind]}
              </Label>
              {suggestion && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-xs"
                  onClick={() => set(kind, suggestion)}
                >
                  <Sparkles className="me-1 h-3 w-3" aria-hidden />
                  {t('ticketingIntegration.issueTypes.useSuggestion', 'Use {name}', {
                    name: suggestion.name,
                  })}
                </Button>
              )}
            </div>
            <Select
              value={chosen?.id || NONE}
              onValueChange={(v) =>
                set(kind, v === NONE ? undefined : types.find((it) => it.id === v))
              }
              disabled={isLoading}
            >
              <SelectTrigger id={selectId} className="h-8">
                <SelectValue
                  placeholder={t('ticketingIntegration.issueTypes.loading', 'Loading issue types…')}
                />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NONE}>
                  {t('ticketingIntegration.issueTypes.stock', 'Default ({name})', {
                    name: STOCK_ISSUE_TYPES[kind],
                  })}
                </SelectItem>
                {chosen?.id && !known && (
                  <SelectItem value={chosen.id}>
                    {t('ticketingIntegration.issueTypes.missing', '{name} (not in this project)', {
                      name: chosen.name || chosen.id,
                    })}
                  </SelectItem>
                )}
                {types.map((it) => (
                  <SelectItem key={it.id} value={it.id}>
                    {it.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-xs">
              {kind === 'epic' ? (
                <span>
                  {t(
                    'ticketingIntegration.issueTypes.epicFields',
                    'Campaign epics use the built-in fields (summary, description, labels).'
                  )}
                </span>
              ) : profile && profile.published_version > 0 ? (
                <>
                  <Badge variant="outline">
                    {t(
                      'ticketingIntegration.issueTypes.mapped',
                      'Fields and statuses: mapping v{v}',
                      {
                        v: profile.published_version,
                      }
                    )}
                  </Badge>
                  {profile.drifted && (
                    <Badge variant="destructive">
                      <TriangleAlert className="me-1 h-3 w-3" aria-hidden />
                      {t('ticketMapping.list.drifted', 'Jira changed')}
                    </Badge>
                  )}
                  <Link
                    href={`/settings/integrations/ticketing/mappings/${profile.id}`}
                    className="underline-offset-2 hover:underline"
                  >
                    {t('ticketingIntegration.issueTypes.openMapping', 'Open the mapping')}
                  </Link>
                </>
              ) : (
                <>
                  <span>
                    {t(
                      'ticketingIntegration.issueTypes.builtIn',
                      'Built-in fields; a type with required custom fields needs a mapping.'
                    )}
                  </span>
                  {chosen?.id && (
                    <Link
                      href={`/settings/integrations/ticketing/mappings?new=1&integration=${encodeURIComponent(integrationId)}&kind=${kind}&project=${encodeURIComponent(project)}&type=${encodeURIComponent(chosen.id)}`}
                      className="inline-flex items-center underline-offset-2 hover:underline"
                    >
                      <ArrowLeftRight className="me-1 h-3 w-3" aria-hidden />
                      {profile
                        ? t('ticketingIntegration.issueTypes.publishMapping', 'Publish its mapping')
                        : t('ticketingIntegration.issueTypes.mapFields', 'Map fields and statuses')}
                    </Link>
                  )}
                </>
              )}
            </div>
            {problem && (
              <p className="text-destructive flex items-start gap-1 text-xs" role="status">
                <TriangleAlert className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
                {t(
                  'ticketingIntegration.issueTypes.refused',
                  'Jira refused the last {type} issue because of: {fields}. Choose the type again or map these fields.',
                  {
                    type: problem.issue_type || kindLabel[kind],
                    fields: (problem.fields ?? []).join(', '),
                  }
                )}
              </p>
            )}
          </div>
        )
      })}
      <p className="text-muted-foreground text-xs">
        {t(
          'ticketingIntegration.issueTypes.checkedOnSave',
          'Saving checks the chosen types with Jira: a type must exist in the project, must not be a sub-task type, and every required field must be filled by {product}.'
        )}
      </p>
    </div>
  )
}
