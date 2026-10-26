'use client'

/**
 * Members step of the create group wizard: three ways to fill a group, in one
 * place. Rule (automatic, kept up to date), Pick (choose assets), Paste (a
 * list of names, addresses, ranges or URLs). They combine: the group holds the
 * rule's matches, plus what is picked or pasted.
 */

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import type { Asset } from '@/features/assets/types'
import { AddAssetsStep } from '../create-group/add-assets-step'
import type { CreateGroupFormData } from '../create-group/types'
import { isDraftEmpty } from '../../lib/group-rule'
import { PasteEditor } from './paste-editor'
import { RuleEditor } from './rule-editor'

interface MembersStepProps {
  data: CreateGroupFormData
  onChange: (data: Partial<CreateGroupFormData>) => void
  ungroupedAssets: Asset[]
  onSearchChange?: (search: string) => void
}

export function MembersStep({ data, onChange, ungroupedAssets, onSearchChange }: MembersStepProps) {
  const { t } = useTranslation()
  const picked = data.selectedAssetIds.length + data.newAssets.length
  const ruleOn = !isDraftEmpty(data.rule)
  const pasted = data.pasteText.trim() !== ''
  const dot = (on: boolean) =>
    on ? (
      <span className="ms-1.5 inline-block h-1.5 w-1.5 rounded-full bg-primary" aria-hidden />
    ) : null
  return (
    <Tabs defaultValue="rule" className="gap-0" data-testid="members-step">
      <div className="px-6 pt-4">
        <p className="mb-3 text-sm text-muted-foreground">
          {t(
            'assetGroups.members.intro',
            'Fill the group by a rule that keeps itself up to date, by picking assets, by pasting a list, or all three.'
          )}
        </p>
        <TabsList>
          <TabsTrigger value="rule">
            {t('assetGroups.members.tab.rule', 'Rule')}
            {dot(ruleOn)}
          </TabsTrigger>
          <TabsTrigger value="pick">
            {t('assetGroups.members.tab.pick', 'Pick')}
            {picked > 0 ? <span className="ms-1.5 text-xs tabular-nums">{picked}</span> : null}
          </TabsTrigger>
          <TabsTrigger value="paste">
            {t('assetGroups.members.tab.paste', 'Paste')}
            {dot(pasted)}
          </TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="rule" className="p-6">
        <RuleEditor draft={data.rule} onChange={(rule) => onChange({ rule })} />
      </TabsContent>
      <TabsContent value="pick">
        <AddAssetsStep
          data={data}
          onChange={onChange}
          ungroupedAssets={ungroupedAssets}
          onSearchChange={onSearchChange}
        />
      </TabsContent>
      <TabsContent value="paste" className="p-6">
        <PasteEditor
          text={data.pasteText}
          onTextChange={(pasteText) => onChange({ pasteText })}
          createMissing={data.pasteCreateMissing}
          onCreateMissingChange={(pasteCreateMissing) => onChange({ pasteCreateMissing })}
        />
      </TabsContent>
    </Tabs>
  )
}
