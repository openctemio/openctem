'use client'

/**
 * Members of an existing group: the rule that fills it (set, change, remove)
 * and a pasted list. Used by the edit dialog, so the group can be changed the
 * same way it was created. Picking assets stays on the group's Assets tab.
 */

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { invalidateGroupMembership, setGroupRule } from '../../api/use-group-rule-api'
import {
  documentToDraft,
  draftToDocument,
  EMPTY_RULE_DRAFT,
  invalidDomains,
  isDraftEmpty,
  type RuleDraft,
} from '../../lib/group-rule'
import type { AssetGroup, GroupRuleImpact } from '../../types'
import { ImpactNotice } from './impact-notice'
import { PasteEditor } from './paste-editor'
import { RuleEditor } from './rule-editor'
import { RuleStatusNote } from './rule-status-note'

interface GroupMembersSectionProps {
  group: AssetGroup
  /** Called after the rule or the members changed. */
  onChanged?: () => void
}

export function GroupMembersSection({ group, onChanged }: GroupMembersSectionProps) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<RuleDraft>(
    group.rule ? documentToDraft(group.rule.document) : EMPTY_RULE_DRAFT
  )
  const [saving, setSaving] = useState(false)
  const [impact, setImpact] = useState<GroupRuleImpact | undefined>()
  const [text, setText] = useState('')
  const [createMissing, setCreateMissing] = useState(false)

  const empty = isDraftEmpty(draft)
  const badDomains = invalidDomains(draft).length > 0

  const save = async (rule: ReturnType<typeof draftToDocument> | null) => {
    setSaving(true)
    try {
      const res = await setGroupRule(group.id, rule)
      setImpact(res.impact)
      await invalidateGroupMembership(group.id)
      toast.success(
        rule
          ? t('assetGroups.members.rule.saved', 'Rule saved: {joined} joined, {left} left', {
              joined: res.joined,
              left: res.left,
            })
          : t('assetGroups.members.rule.removed', 'Rule removed: the members stay in the group')
      )
      if (!rule) setDraft(EMPTY_RULE_DRAFT)
      onChanged?.()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('assetGroups.members.rule.saveFailed', 'The rule could not be saved'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Tabs defaultValue="rule" className="gap-3" data-testid="group-members-section">
      <TabsList>
        <TabsTrigger value="rule">{t('assetGroups.members.tab.rule', 'Rule')}</TabsTrigger>
        <TabsTrigger value="paste">{t('assetGroups.members.tab.paste', 'Paste')}</TabsTrigger>
      </TabsList>
      <TabsContent value="rule" className="space-y-4">
        {group.rule ? <RuleStatusNote rule={group.rule} /> : null}
        <RuleEditor draft={draft} onChange={setDraft} groupId={group.id} />
        <ImpactNotice impact={impact} />
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            disabled={saving || empty || badDomains}
            onClick={() => save(draftToDocument(draft))}
          >
            {saving ? <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden /> : null}
            {t('assetGroups.members.rule.save', 'Save rule')}
          </Button>
          {group.rule ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={saving}
              onClick={() => save(null)}
            >
              {t('assetGroups.members.rule.remove', 'Remove rule')}
            </Button>
          ) : null}
        </div>
      </TabsContent>
      <TabsContent value="paste">
        <PasteEditor
          text={text}
          onTextChange={setText}
          createMissing={createMissing}
          onCreateMissingChange={setCreateMissing}
          groupId={group.id}
          onApplied={() => {
            setText('')
            onChanged?.()
          }}
        />
      </TabsContent>
    </Tabs>
  )
}
