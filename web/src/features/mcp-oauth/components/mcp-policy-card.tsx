'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
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
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { getErrorMessage } from '@/lib/api/error-handler'

import { type McpPolicyUpdate, updateMcpPolicy, useMcpPolicy } from '../api/connections'

interface McpPolicyCardProps {
  canEdit: boolean
}

/** Host names, one per line or comma-separated. */
export function parseHosts(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
}

/**
 * The organization's policy for AI applications (RFC-062 §8): whether MCP is
 * on, which applications may connect, which access members may grant,
 * whether API keys work on MCP, and how long a connection lasts. Saving
 * needs a recent sign-in (the shared client asks for it).
 */
export function McpPolicyCard({ canEdit }: McpPolicyCardProps) {
  const { data, isLoading, error } = useMcpPolicy(true)
  const [draft, setDraft] = useState<McpPolicyUpdate | null>(null)
  const [hostsText, setHostsText] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!data) return
    setDraft({
      enabled: data.enabled,
      any_client: data.any_client,
      client_hosts: data.client_hosts,
      scopes: data.scopes,
      api_keys_allowed: data.api_keys_allowed,
      refresh_days: data.refresh_days,
      require_dpop: data.require_dpop,
    })
    setHostsText(data.client_hosts.join('\n'))
  }, [data])

  if (isLoading || (!draft && !error)) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-1/3" />
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-2/3" />
        </CardContent>
      </Card>
    )
  }
  if (!data || !draft) {
    return null
  }

  const readScopes = data.available_scopes.filter((s) => !s.write)
  // An empty list on the server means every read scope.
  const selected = new Set(draft.scopes.length ? draft.scopes : readScopes.map((s) => s.scope))
  const set = (patch: Partial<McpPolicyUpdate>) => setDraft({ ...draft, ...patch })
  const toggleScope = (scope: string, on: boolean) => {
    const next = new Set(selected)
    if (on) next.add(scope)
    else next.delete(scope)
    set({ scopes: Array.from(next).sort() })
  }

  const save = async () => {
    setSaving(true)
    try {
      await updateMcpPolicy({ ...draft, client_hosts: parseHosts(hostsText) })
      toast.success('Policy saved. It applies to existing connections at once.')
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not save the policy'))
    } finally {
      setSaving(false)
    }
  }

  const disabled = !canEdit || saving

  return (
    <Card>
      <CardHeader>
        <CardTitle>Organization policy</CardTitle>
        <CardDescription>
          Which AI applications members may connect and what they may let them read. Changes apply
          to existing connections at once.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <Label htmlFor="mcp-enabled">AI application access</Label>
            <p className="text-muted-foreground text-sm">
              Off: no application or API key can use the MCP server.
            </p>
          </div>
          <Switch
            id="mcp-enabled"
            checked={draft.enabled}
            onCheckedChange={(v) => set({ enabled: v })}
            disabled={disabled}
          />
        </div>

        <div className="flex items-start justify-between gap-4">
          <div>
            <Label htmlFor="mcp-any-client">Allow unverified applications</Label>
            <p className="text-muted-foreground text-sm">
              Off: only applications your organization registered or published on a trusted host
              below.
            </p>
          </div>
          <Switch
            id="mcp-any-client"
            checked={draft.any_client}
            onCheckedChange={(v) => set({ any_client: v })}
            disabled={disabled}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="mcp-hosts">Trusted application hosts</Label>
          <Textarea
            id="mcp-hosts"
            value={hostsText}
            onChange={(e) => setHostsText(e.target.value)}
            placeholder={'assistant.example.com\nide.example.org'}
            rows={3}
            disabled={disabled}
          />
          <p className="text-muted-foreground text-xs">
            Host names only, one per line. Applications whose identity document is published on
            these hosts count as verified.
          </p>
          {data.platform_client_hosts.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 text-xs">
              <span className="text-muted-foreground">Trusted by the platform:</span>
              {data.platform_client_hosts.map((h) => (
                <Badge key={h} variant="outline" className="font-mono text-xs">
                  {h}
                </Badge>
              ))}
            </div>
          )}
        </div>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Access members may grant</legend>
          {readScopes.map((s) => (
            <label key={s.scope} className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={selected.has(s.scope)}
                onCheckedChange={(v) => toggleScope(s.scope, v === true)}
                disabled={disabled}
              />
              {s.title}
            </label>
          ))}
        </fieldset>

        <div className="flex items-start justify-between gap-4">
          <div>
            <Label htmlFor="mcp-keys">API keys on the MCP server</Label>
            <p className="text-muted-foreground text-sm">
              For scripts without a person; they still work on the REST API.
            </p>
          </div>
          <Switch
            id="mcp-keys"
            checked={draft.api_keys_allowed}
            onCheckedChange={(v) => set({ api_keys_allowed: v })}
            disabled={disabled}
          />
        </div>

        <div className="flex items-start justify-between gap-4">
          <div>
            <Label htmlFor="mcp-dpop">Require proof of possession (DPoP)</Label>
            <p className="text-muted-foreground text-sm">
              Applications must sign every request with their own key, so a copied token is useless.
              Applications without DPoP support can no longer connect.
            </p>
          </div>
          <Switch
            id="mcp-dpop"
            checked={draft.require_dpop}
            onCheckedChange={(v) => set({ require_dpop: v })}
            disabled={disabled}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="mcp-days">Connections last (days)</Label>
          <Input
            id="mcp-days"
            type="number"
            min={1}
            max={90}
            className="w-32"
            value={draft.refresh_days || data.effective_refresh_days}
            onChange={(e) => set({ refresh_days: Number(e.target.value) || 0 })}
            disabled={disabled}
          />
          <p className="text-muted-foreground text-xs">
            After this, the person approves the application again. 1 to 90.
          </p>
        </div>
      </CardContent>
      {canEdit && (
        <CardFooter className="justify-end">
          <Button onClick={() => void save()} disabled={saving || selected.size === 0}>
            {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
            Save policy
          </Button>
        </CardFooter>
      )}
    </Card>
  )
}
