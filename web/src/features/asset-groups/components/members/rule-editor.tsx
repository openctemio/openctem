'use client'

/**
 * The rule of a group that fills itself: domains (with or without the names
 * below them), asset filters (the same ones as the Assets list), the scope
 * entries that cover an asset, and the option to bring the services, URLs and
 * certificates of the matched hosts. Beside it, the live preview.
 */

import { useMemo } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { TagInput } from '@/components/ui/tag-input'
import { MultiSelect } from '@/features/shared/components/multi-select'
import { useTranslation } from '@/context/i18n-provider'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { useScopeTargetsApi } from '@/features/scope/api/use-scope-api'
import { draftToDocument, invalidDomains, isDraftEmpty, type RuleDraft } from '../../lib/group-rule'
import { RulePreview } from './rule-preview'
import { RATED_CRITICALITY_LEVELS } from '@/lib/criticality'

const CRITICALITIES = RATED_CRITICALITY_LEVELS
const ENVIRONMENTS = ['production', 'staging', 'development', 'testing', 'dr']

interface RuleEditorProps {
  draft: RuleDraft
  onChange: (next: RuleDraft) => void
  /** Set for a group being edited (adds who would join and leave). */
  groupId?: string
}

export function RuleEditor({ draft, onChange, groupId }: RuleEditorProps) {
  const { t } = useTranslation()
  const { registry } = useAssetTypeRegistry()
  const { data: scopeTargets } = useScopeTargetsApi(
    { status: 'active', per_page: 100 },
    { onError: () => undefined, shouldRetryOnError: false }
  )

  const typeOptions = useMemo(
    () =>
      (registry?.types ?? [])
        .filter((d) => !d.alias_of && d.type)
        .map((d) => ({ value: String(d.type), label: d.label ?? String(d.type) })),
    [registry]
  )
  const criticalityOptions = CRITICALITIES.map((c) => ({
    value: c,
    label: t(`criticality.${c}`, c),
  }))
  const environmentOptions = ENVIRONMENTS.map((e) => ({
    value: e,
    label: t(`assetGroups.environment.${e}`, e),
  }))
  const scopeOptions = (scopeTargets?.data ?? []).map((s) => ({
    value: s.id ?? '',
    label: s.pattern ?? s.id ?? '',
  }))

  const set = (patch: Partial<RuleDraft>) => onChange({ ...draft, ...patch })
  const bad = invalidDomains(draft)
  const empty = isDraftEmpty(draft)
  const blocked =
    bad.length > 0
      ? t('assetGroups.members.rule.badDomains', 'Not a domain name: {names}', {
          names: bad.slice(0, 3).join(', '),
        })
      : undefined
  const document = empty ? null : draftToDocument(draft)

  return (
    <div
      className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]"
      data-testid="rule-editor"
    >
      <div className="space-y-5">
        <div className="space-y-2">
          <Label htmlFor="rule-domains">{t('assetGroups.members.rule.domains', 'Domains')}</Label>
          <Textarea
            id="rule-domains"
            rows={3}
            value={draft.domainsText}
            onChange={(e) => set({ domainsText: e.target.value })}
            placeholder={t(
              'assetGroups.members.rule.domainsPlaceholder',
              'example.com or *.example.com, one per line'
            )}
            aria-invalid={bad.length > 0}
            aria-describedby="rule-domains-help"
            className="font-mono text-sm"
          />
          <p id="rule-domains-help" className="text-xs text-muted-foreground">
            {t(
              'assetGroups.members.rule.domainsHelp',
              'A name matches only on a whole label: example.com never matches evilexample.com.'
            )}
          </p>
          <div className="flex items-center gap-2">
            <Checkbox
              id="rule-subdomains"
              checked={draft.subdomains}
              onCheckedChange={(v) => set({ subdomains: v === true })}
            />
            <Label htmlFor="rule-subdomains" className="font-normal">
              {t('assetGroups.members.rule.subdomains', 'Include subdomains')}
            </Label>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>{t('assetGroups.members.rule.types', 'Asset types')}</Label>
            <MultiSelect
              options={typeOptions}
              value={draft.types}
              onChange={(types) => set({ types })}
              placeholder={t('assetGroups.members.rule.anyType', 'Any type')}
            />
          </div>
          <div className="space-y-2">
            <Label>{t('assetGroups.members.rule.criticality', 'Criticality')}</Label>
            <MultiSelect
              options={criticalityOptions}
              value={draft.criticalities}
              onChange={(criticalities) => set({ criticalities })}
              placeholder={t('assetGroups.members.rule.anyCriticality', 'Any criticality')}
            />
          </div>
          <div className="space-y-2">
            <Label>{t('assetGroups.members.rule.environment', 'Environment')}</Label>
            <MultiSelect
              options={environmentOptions}
              value={draft.environments}
              onChange={(environments) => set({ environments })}
              placeholder={t('assetGroups.members.rule.anyEnvironment', 'Any environment')}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="rule-tags">{t('assetGroups.members.rule.tags', 'Tags (any of)')}</Label>
            <TagInput
              id="rule-tags"
              value={draft.tags}
              onChange={(tags) => set({ tags })}
              placeholder={t(
                'assetGroups.members.rule.tagsPlaceholder',
                'Type a tag and press Enter'
              )}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="rule-search">
            {t('assetGroups.members.rule.search', 'Name contains')}
          </Label>
          <Input
            id="rule-search"
            value={draft.search}
            onChange={(e) => set({ search: e.target.value })}
            maxLength={255}
          />
        </div>

        {scopeOptions.length > 0 ? (
          <div className="space-y-2">
            <Label>{t('assetGroups.members.rule.coveredBy', 'Covered by scope entry')}</Label>
            <MultiSelect
              options={scopeOptions}
              value={draft.coveredBy}
              onChange={(coveredBy) => set({ coveredBy })}
              placeholder={t('assetGroups.members.rule.anyScope', 'Any scope entry')}
            />
          </div>
        ) : null}

        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <Checkbox
              id="rule-internet"
              checked={draft.internetFacing}
              onCheckedChange={(v) => set({ internetFacing: v === true })}
            />
            <Label htmlFor="rule-internet" className="font-normal">
              {t('assetGroups.members.rule.internetFacing', 'Only internet-facing assets')}
            </Label>
          </div>
          <div className="flex items-start gap-2">
            <Checkbox
              id="rule-related"
              checked={draft.includeRelated}
              onCheckedChange={(v) => set({ includeRelated: v === true })}
              className="mt-0.5"
            />
            <div>
              <Label htmlFor="rule-related" className="font-normal">
                {t('assetGroups.members.rule.related', 'Include related assets')}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  'assetGroups.members.rule.relatedHelp',
                  'The services, URLs and certificates of the hosts the rule matches.'
                )}
              </p>
            </div>
          </div>
        </div>
      </div>

      <aside
        className="space-y-2 rounded-lg border bg-muted/20 p-4"
        aria-label={t('assetGroups.members.preview.title', 'Preview')}
      >
        <h3 className="text-sm font-semibold">
          {t('assetGroups.members.preview.title', 'Preview')}
        </h3>
        <RulePreview rule={document} groupId={groupId} blockedReason={blocked} />
      </aside>
    </div>
  )
}
