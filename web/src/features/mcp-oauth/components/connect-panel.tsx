'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  KeyRound,
  Loader2,
  Sparkles,
} from 'lucide-react'
import { toast } from 'sonner'

import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
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
import { useCreateApiKey } from '@/features/api-keys/api/use-api-keys'
import { API_KEY_EXPIRY_OPTIONS, DEFAULT_API_KEY_EXPIRY_DAYS } from '@/features/api-keys/lib/expiry'
import type { CreateAPIKeyResponse } from '@/features/api-keys/types/api-key.types'
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'

// A minted MCP key carries exactly the read scopes below, nothing more. The
// user picks the key's purpose so it maps to what the server's MCP tools and
// prompts require. Scope strings mirror the backend permission constants
// (src/lib/permissions/constants.ts).
type PresetId = 'general' | 'pentest'

const KEY_PRESETS: Record<PresetId, { scopes: string[] }> = {
  general: { scopes: ['findings:read', 'assets:read', 'compliance:frameworks:read'] },
  pentest: {
    scopes: [
      'pentest:campaigns:read',
      'pentest:findings:read',
      'pentest:retests:read',
      'pentest:templates:read',
    ],
  },
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        if (await copyToClipboard(value)) {
          setCopied(true)
          toast.success(t('mcp.connect.copied', '{label} copied', { label }))
          setTimeout(() => setCopied(false), 1500)
        }
      }}
    >
      {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      <span className="ml-1.5">{t('mcp.connect.copy', 'Copy')}</span>
    </Button>
  )
}

interface ConnectPanelProps {
  keyDialogOpen: boolean
  onKeyDialogOpenChange: (open: boolean) => void
  canWriteKeys: boolean
}

/**
 * How to connect: OAuth sign-in from the AI application (the main path),
 * a script with an API key (secondary) and the pentest report-writing guide
 * (folded away).
 */
export function ConnectPanel({
  keyDialogOpen,
  onKeyDialogOpenChange,
  canWriteKeys,
}: ConnectPanelProps) {
  const { t } = useTranslation()
  const defaultName = (id: PresetId) =>
    id === 'general'
      ? t('mcp.key.defaultName.general', 'MCP read access')
      : t('mcp.key.defaultName.pentest', 'Pentest report writer')
  const [preset, setPreset] = useState<PresetId>('general')
  const [name, setName] = useState(() => defaultName('general'))
  const [expiry, setExpiry] = useState<string>(DEFAULT_API_KEY_EXPIRY_DAYS)
  const [created, setCreated] = useState<CreateAPIKeyResponse | null>(null)
  const [guideOpen, setGuideOpen] = useState(false)
  const { trigger, isMutating } = useCreateApiKey()
  const activePreset = KEY_PRESETS[preset]

  const presetLabel = (id: PresetId) =>
    id === 'general'
      ? t('mcp.key.preset.general', 'General read access (findings, assets, compliance)')
      : t(
          'mcp.key.preset.pentest',
          'Pentest report writing (campaigns, findings, retests, templates)'
        )

  // Switching purpose swaps the default key name unless the user typed one.
  const handlePresetChange = (next: PresetId) => {
    const isDefaultName = (Object.keys(KEY_PRESETS) as PresetId[]).some(
      (id) => defaultName(id) === name.trim()
    )
    if (isDefaultName || !name.trim()) setName(defaultName(next))
    setPreset(next)
  }

  // The MCP endpoint is served under the API path on this origin (the Next
  // proxy forwards /api/v1/* to the backend).
  const [endpoint, setEndpoint] = useState('/api/v1/mcp')
  useEffect(() => {
    setEndpoint(`${window.location.origin}/api/v1/mcp`)
  }, [])

  const oauthConfigJson = useMemo(
    () => JSON.stringify({ mcpServers: { openctem: { type: 'http', url: endpoint } } }, null, 2),
    [endpoint]
  )
  const keyConfigJson = useMemo(() => {
    const key = created?.key ?? 'oct_YOUR_KEY_HERE'
    return JSON.stringify(
      {
        mcpServers: {
          openctem: { type: 'http', url: endpoint, headers: { Authorization: `Bearer ${key}` } },
        },
      },
      null,
      2
    )
  }, [created, endpoint])

  const handleCreate = async () => {
    const trimmed = name.trim()
    if (!trimmed) {
      toast.error(t('mcp.key.nameRequired', 'Give the key a name'))
      return
    }
    try {
      const res = await trigger({
        name: trimmed,
        description: t('mcp.key.description', 'MCP connection key (read-only AI access)'),
        scopes: activePreset.scopes,
        expires_in_days: Number(expiry),
      })
      setCreated(res ?? null)
      onKeyDialogOpenChange(false)
      toast.success(t('mcp.key.created', 'Key generated. Copy it now: it is shown only once.'))
    } catch (err) {
      toast.error(getErrorMessage(err, t('mcp.key.createFailed', 'Could not generate the key')))
    }
  }

  const configLabel = t('mcp.connect.configuration', 'Configuration')

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle>{t('mcp.connect.title', 'Connect an AI assistant')}</CardTitle>
          <CardDescription>
            {t(
              'mcp.connect.description',
              'Add this server to your AI assistant. On first use it opens {product} in your browser: you sign in, choose what it may read, and approve. There is no key to copy.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <Label>{t('mcp.connect.clientConfig', 'Client configuration')}</Label>
            <CopyButton value={oauthConfigJson} label={configLabel} />
          </div>
          <pre className="bg-muted overflow-x-auto rounded-md p-4 text-xs">
            <code>{oauthConfigJson}</code>
          </pre>
          <p className="text-muted-foreground text-xs">
            {t(
              'mcp.connect.otherHost',
              'If your {product} API is on a different host, replace the URL accordingly.'
            )}
          </p>
          <Button asChild variant="link" className="h-auto p-0 whitespace-normal text-start">
            <Link href="/account/connected-apps">
              {t('mcp.connect.yourConnections', 'See and disconnect your connected applications')}
              <ArrowRight className="ms-1 h-3.5 w-3.5 shrink-0" aria-hidden />
            </Link>
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div className="space-y-1.5">
            <CardTitle>{t('mcp.key.title', 'Connect a script with an API key')}</CardTitle>
            <CardDescription>
              {t(
                'mcp.key.cardDescription',
                'For automation without a person at the keyboard. The key is read-only, scoped to its purpose and bound to your account.'
              )}
            </CardDescription>
          </div>
          {canWriteKeys && (
            <Button
              size="sm"
              variant="outline"
              className="shrink-0"
              onClick={() => onKeyDialogOpenChange(true)}
            >
              <KeyRound className="me-2 h-4 w-4" aria-hidden />
              {t('mcp.key.generate', 'Generate key')}
            </Button>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          {!canWriteKeys && (
            <p className="text-muted-foreground text-sm">
              {t('mcp.key.noPermission', 'You need the API-keys permission to generate a key.')}
            </p>
          )}
          {created && (
            <div className="border-primary/40 bg-primary/5 space-y-3 rounded-md border p-4">
              <div className="flex items-start gap-2 text-sm">
                <AlertTriangle className="text-primary mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                <p>
                  {t(
                    'mcp.key.copyNow',
                    'Copy your key now: for security it is shown only once. It is already in the configuration below.'
                  )}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Input readOnly value={created.key} className="font-mono text-xs" />
                <CopyButton value={created.key} label={t('mcp.key.key', 'Key')} />
              </div>
            </div>
          )}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>{t('mcp.connect.clientConfig', 'Client configuration')}</Label>
              <CopyButton value={keyConfigJson} label={configLabel} />
            </div>
            <pre className="bg-muted overflow-x-auto rounded-md p-4 text-xs">
              <code>{keyConfigJson}</code>
            </pre>
          </div>
        </CardContent>
      </Card>

      <Collapsible open={guideOpen} onOpenChange={setGuideOpen}>
        <Card className="gap-0 py-0">
          <CollapsibleTrigger className="flex w-full items-center justify-between gap-3 px-6 py-4 text-start">
            <span className="text-sm font-medium">
              {t('mcp.guide.title', 'Write pentest reports with an AI assistant')}
            </span>
            <ChevronDown
              className={cn('h-4 w-4 transition-transform', guideOpen && 'rotate-180')}
              aria-hidden
            />
          </CollapsibleTrigger>
          <CollapsibleContent>
            <CardContent className="space-y-4 pb-6 text-sm">
              <ol className="list-decimal space-y-2 ps-5">
                <li>
                  {t(
                    'mcp.guide.step1',
                    'Pull context with the read tools get_campaign, list_campaign_findings, list_retests, list_finding_templates and campaign_report_stats.'
                  )}
                </li>
                <li>
                  {t(
                    'mcp.guide.step2',
                    'Draft each section with the prompts exec_summary, finding_writeup, remediation_guidance and attack_narrative.'
                  )}
                </li>
                <li>
                  {t(
                    'mcp.guide.step3',
                    'Review the draft and paste it into the finding or campaign editor. Nothing is written by the assistant.'
                  )}
                </li>
              </ol>
              <div className="border-primary/40 bg-primary/5 flex items-start gap-2 rounded-md border p-3">
                <Sparkles className="text-primary mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                <p className="text-muted-foreground">
                  {t(
                    'mcp.guide.evidenceNote',
                    'Evidence files and attachments are never sent to the AI: the tools return only counts.'
                  )}
                </p>
              </div>
            </CardContent>
          </CollapsibleContent>
        </Card>
      </Collapsible>

      <Dialog open={keyDialogOpen} onOpenChange={onKeyDialogOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('mcp.key.dialogTitle', 'Generate an MCP key')}</DialogTitle>
            <DialogDescription>
              {t(
                'mcp.key.dialogDesc',
                'Read-only and bound to your account: it stops working if your membership is suspended or removed.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="mcp-key-purpose">{t('mcp.key.purpose', 'Purpose')}</Label>
                <Select value={preset} onValueChange={(v) => handlePresetChange(v as PresetId)}>
                  <SelectTrigger id="mcp-key-purpose">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(Object.keys(KEY_PRESETS) as PresetId[]).map((id) => (
                      <SelectItem key={id} value={id}>
                        {presetLabel(id)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {activePreset.scopes.map((s) => (
                    <Badge key={s} variant="outline" className="font-mono text-xs">
                      {s}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="mcp-key-name">{t('mcp.key.name', 'Name')}</Label>
                <Input
                  id="mcp-key-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={t('mcp.key.namePlaceholder', 'e.g. Report script')}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mcp-key-expiry">{t('mcp.key.expires', 'Expires')}</Label>
                <Select value={expiry} onValueChange={setExpiry}>
                  <SelectTrigger id="mcp-key-expiry">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {API_KEY_EXPIRY_OPTIONS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {t(`mcp.key.expiry.${o.value}`, o.label)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => onKeyDialogOpenChange(false)}
              disabled={isMutating}
            >
              {t('mcp.common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={isMutating}>
              {isMutating && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
              {t('mcp.key.generateShort', 'Generate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
