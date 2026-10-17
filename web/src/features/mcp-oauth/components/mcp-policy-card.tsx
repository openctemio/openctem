'use client'

import { useEffect, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { useProfileLabels } from '@/features/pentest/lib/use-pentest-labels'
import { CAMPAIGN_TLPS, type CampaignTLP } from '@/features/pentest/types'
import { getErrorMessage } from '@/lib/api/error-handler'

import { type McpPolicy, type McpPolicyUpdate, patchMcpPolicy } from '../api/connections'
import { useMcpLabels } from '../lib/use-mcp-labels'

interface McpPolicyCardProps {
  policy: McpPolicy
  canEdit: boolean
}

type PolicyDraft = Omit<McpPolicyUpdate, 'any_client' | 'client_hosts'>

/** The draft holds the explicit selection (the server's empty list = every read scope). */
function draftOf(p: McpPolicy): PolicyDraft {
  return {
    enabled: p.enabled,
    scopes: effectiveScopes(p),
    api_keys_allowed: p.api_keys_allowed,
    refresh_days: p.refresh_days,
    require_dpop: p.require_dpop,
    max_tlp: p.max_tlp,
  }
}

/** An empty scope list on the server means every read scope. */
export function effectiveScopes(p: Pick<McpPolicy, 'scopes' | 'available_scopes'>): string[] {
  return p.scopes.length ? p.scopes : p.available_scopes.filter((s) => !s.write).map((s) => s.scope)
}

/**
 * What AI assistants may do in the organization and within which limits
 * (RFC-062 §8): on or off, the access members may grant (read, and the
 * write scope that adds person-confirmed comments), connection lifetime,
 * proof of possession, API keys and the TLP ceiling. Which applications may
 * connect lives on the Applications tab. Saving needs a recent sign-in (the
 * shared client asks for it).
 */
export function McpPolicyCard({ policy, canEdit }: McpPolicyCardProps) {
  const { t } = useTranslation()
  const { tlpLabel } = useProfileLabels()
  const { scopeTitle } = useMcpLabels()
  const [draft, setDraft] = useState<PolicyDraft>(() => draftOf(policy))
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setDraft(draftOf(policy))
  }, [policy])

  const readScopes = policy.available_scopes.filter((s) => !s.write)
  const writeScopes = policy.available_scopes.filter((s) => s.write)
  const selected = new Set(draft.scopes)
  const readCount = readScopes.filter((s) => selected.has(s.scope)).length
  const set = (patch: Partial<PolicyDraft>) => setDraft((d) => ({ ...d, ...patch }))
  const toggleScope = (scope: string, on: boolean) => {
    const next = new Set(selected)
    if (on) next.add(scope)
    else next.delete(scope)
    set({ scopes: Array.from(next).sort() })
  }

  const save = async () => {
    setSaving(true)
    try {
      // Exactly every read scope is stored as the empty list, so read scopes
      // added later are included too.
      const allReads = readScopes.map((s) => s.scope).sort()
      const chosen = [...draft.scopes].sort()
      const scopes = chosen.join() === allReads.join() ? [] : chosen
      await patchMcpPolicy(policy, { ...draft, scopes })
      toast.success(
        t('mcp.policy.saved', 'Policy saved. It applies to existing connections at once.')
      )
    } catch (err) {
      toast.error(getErrorMessage(err, t('mcp.policy.saveFailed', 'Could not save the policy')))
    } finally {
      setSaving(false)
    }
  }

  const disabled = !canEdit || saving

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('mcp.policy.title', 'Policy')}</CardTitle>
        <CardDescription>
          {t(
            'mcp.policy.description',
            'What AI assistants may do in this organization. Changes apply to existing connections at once.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="flex items-start justify-between gap-4">
          <div>
            <Label htmlFor="mcp-enabled" className="text-base">
              {t('mcp.policy.enabled', 'AI assistants')}
            </Label>
            <p className="text-muted-foreground text-sm">
              {t(
                'mcp.policy.enabledHint',
                'Off: no application or API key can use the MCP server, and existing connections stop working.'
              )}
            </p>
          </div>
          <Switch
            id="mcp-enabled"
            checked={draft.enabled}
            onCheckedChange={(v) => set({ enabled: v })}
            disabled={disabled}
          />
        </section>

        <Separator />

        <section aria-labelledby="mcp-capabilities" className="space-y-4">
          <div>
            <h3 id="mcp-capabilities" className="text-base font-medium">
              {t('mcp.policy.capabilities', 'What assistants may do')}
            </h3>
            <p className="text-muted-foreground text-sm">
              {t(
                'mcp.policy.capabilitiesHint',
                'The most a member can let an application do. It never gets more than the member can do themselves.'
              )}
            </p>
          </div>
          <fieldset className="space-y-2">
            <legend className="text-muted-foreground mb-1 text-xs font-medium">
              {t('mcp.policy.read', 'Read')}
            </legend>
            {readScopes.map((s) => (
              <label key={s.scope} className="flex items-start gap-2 text-sm">
                <Checkbox
                  className="mt-0.5"
                  checked={selected.has(s.scope)}
                  onCheckedChange={(v) => toggleScope(s.scope, v === true)}
                  disabled={disabled}
                />
                {scopeTitle(s.scope, s.title)}
              </label>
            ))}
          </fieldset>
          {writeScopes.length > 0 && (
            <fieldset className="space-y-2">
              <legend className="text-muted-foreground mb-1 text-xs font-medium">
                {t('mcp.policy.change', 'Change')}
              </legend>
              {writeScopes.map((s) => (
                <label key={s.scope} className="flex items-start gap-2 text-sm">
                  <Checkbox
                    className="mt-0.5"
                    checked={selected.has(s.scope)}
                    onCheckedChange={(v) => toggleScope(s.scope, v === true)}
                    disabled={disabled}
                  />
                  <span className="space-y-1">
                    <span className="flex flex-wrap items-center gap-2">
                      {scopeTitle(s.scope, s.title)}
                      <Badge variant="outline" className="gap-1 text-xs">
                        <AlertTriangle className="h-3 w-3" aria-hidden />
                        {t('mcp.consent.changesData', 'Changes data')}
                      </Badge>
                    </span>
                    <span className="text-muted-foreground block text-xs">
                      {t(
                        'mcp.policy.writeHint',
                        'Off by default. The application asks for it only when it needs it, the member approves it, and each comment waits for the member to confirm it in {product} before it is saved.'
                      )}
                    </span>
                  </span>
                </label>
              ))}
            </fieldset>
          )}
          {readCount === 0 && (
            <p className="text-destructive text-xs" role="alert">
              {t('mcp.policy.needOneRead', 'Choose at least one thing assistants may read.')}
            </p>
          )}
        </section>

        <Separator />

        <section aria-labelledby="mcp-limits" className="space-y-5">
          <h3 id="mcp-limits" className="text-base font-medium">
            {t('mcp.policy.limits', 'Limits')}
          </h3>
          <div className="grid gap-5 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="mcp-days">{t('mcp.policy.days', 'Connections last (days)')}</Label>
              <Input
                id="mcp-days"
                type="number"
                min={1}
                max={90}
                className="w-32"
                value={draft.refresh_days || policy.effective_refresh_days}
                onChange={(e) => set({ refresh_days: Number(e.target.value) || 0 })}
                disabled={disabled}
                aria-describedby="mcp-days-hint"
              />
              <p id="mcp-days-hint" className="text-muted-foreground text-xs">
                {t(
                  'mcp.policy.daysHint',
                  'After this, the person approves the application again. 1 to 90.'
                )}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mcp-max-tlp">
                {t('mcp.policy.maxTlp', 'Highest TLP sent to AI applications')}
              </Label>
              <Select
                value={draft.max_tlp}
                onValueChange={(v) => set({ max_tlp: v as CampaignTLP })}
                disabled={disabled}
              >
                <SelectTrigger id="mcp-max-tlp" className="w-56" aria-describedby="mcp-tlp-hint">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CAMPAIGN_TLPS.map((l) => (
                    <SelectItem key={l} value={l}>
                      {tlpLabel(l)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p id="mcp-tlp-hint" className="text-muted-foreground text-xs">
                {t(
                  'mcp.policy.maxTlpHint',
                  'Pentest campaigns above this level are never sent to AI applications. A campaign lead can also turn AI assistants off for one campaign.'
                )}
              </p>
            </div>
          </div>

          <div className="flex items-start justify-between gap-4">
            <div>
              <Label htmlFor="mcp-dpop">
                {t('mcp.policy.dpop', 'Require proof of possession (DPoP)')}
              </Label>
              <p className="text-muted-foreground text-sm">
                {t(
                  'mcp.policy.dpopHint',
                  'Applications must sign every request with their own key, so a copied token is useless. Applications without DPoP support can no longer connect.'
                )}
              </p>
            </div>
            <Switch
              id="mcp-dpop"
              checked={draft.require_dpop}
              onCheckedChange={(v) => set({ require_dpop: v })}
              disabled={disabled}
            />
          </div>

          <div className="flex items-start justify-between gap-4">
            <div>
              <Label htmlFor="mcp-keys">
                {t('mcp.policy.apiKeys', 'API keys on the MCP server')}
              </Label>
              <p className="text-muted-foreground text-sm">
                {t(
                  'mcp.policy.apiKeysHint',
                  'For scripts without a person; they still work on the REST API.'
                )}
              </p>
            </div>
            <Switch
              id="mcp-keys"
              checked={draft.api_keys_allowed}
              onCheckedChange={(v) => set({ api_keys_allowed: v })}
              disabled={disabled}
            />
          </div>
        </section>
      </CardContent>
      {canEdit && (
        <CardFooter className="justify-end">
          <Button onClick={() => void save()} disabled={saving || readCount === 0}>
            {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('mcp.policy.save', 'Save policy')}
          </Button>
        </CardFooter>
      )}
    </Card>
  )
}
