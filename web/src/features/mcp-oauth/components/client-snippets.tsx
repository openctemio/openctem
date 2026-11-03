'use client'

import { useMemo, useState } from 'react'

import Link from '@/components/link'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'

import { buildSnippets, CLIENT_IDS, CLIENT_NAMES, type ClientId } from '../lib/client-snippets'
import { SnippetBlock } from './snippet-block'

interface ClientSnippetsProps {
  /** The MCP endpoint of this instance (https://host/api/v1/mcp). */
  endpoint: string
  /** The page where a terminal's code is entered (https://host/oauth/device). */
  deviceUrl: string
}

/**
 * Setup per client, one tab each, plus "Remote or VPS" for a client whose
 * browser is on another machine: the device code sign-in, pasting the
 * redirect back, or forwarding the callback port over SSH.
 */
export function ClientSnippets({ endpoint, deviceUrl }: ClientSnippetsProps) {
  const { t } = useTranslation()
  const [tab, setTab] = useState<ClientId>('claude-code')
  const s = useMemo(() => buildSnippets(endpoint), [endpoint])
  const commands = t('mcp.connect.commands', 'Commands')
  const config = t('mcp.connect.configuration', 'Configuration')
  const step = (text: string) => <p className="text-muted-foreground text-sm">{text}</p>

  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as ClientId)}>
      <TabsList>
        {CLIENT_IDS.map((id) => (
          <TabsTrigger key={id} value={id}>
            {id === 'remote' ? t('mcp.connect.remoteTab', 'Remote or VPS') : CLIENT_NAMES[id]}
          </TabsTrigger>
        ))}
      </TabsList>

      <TabsContent value="claude-code" className="space-y-3 pt-2">
        {step(
          t(
            'mcp.connect.claudeCode.step',
            'Run these in a terminal on the computer where your browser is. The second command opens the sign-in page.'
          )
        )}
        <SnippetBlock label={commands} code={s.claudeCode} />
      </TabsContent>

      <TabsContent value="codex" className="space-y-3 pt-2">
        {step(
          t(
            'mcp.connect.codex.step',
            'Add the server and sign in. Or add the block below to ~/.codex/config.toml and run the login command.'
          )
        )}
        <SnippetBlock label={commands} code={s.codexCli} />
        <SnippetBlock label={config} code={s.codexToml} />
      </TabsContent>

      <TabsContent value="gemini" className="space-y-3 pt-2">
        {step(
          t(
            'mcp.connect.gemini.step',
            'Gemini CLI needs an application id: ask an administrator to register one under Settings, AI assistants (MCP), Applications, with the address shown in redirectUri. Put the id in clientId, add this to ~/.gemini/settings.json, then run /mcp auth openctem.'
          )
        )}
        <SnippetBlock label={config} code={s.geminiJson} />
      </TabsContent>

      <TabsContent value="vscode" className="space-y-3 pt-2">
        {step(
          t(
            'mcp.connect.vscode.step',
            'Add this to .vscode/mcp.json (or your user MCP settings) and start the server; VS Code opens the sign-in page.'
          )
        )}
        <SnippetBlock label={config} code={s.vscodeJson} />
      </TabsContent>

      <TabsContent value="cursor" className="space-y-3 pt-2">
        {step(
          t(
            'mcp.connect.cursor.step',
            'Add this to ~/.cursor/mcp.json; Cursor offers to sign in when the server first connects.'
          )
        )}
        <SnippetBlock label={config} code={s.cursorJson} />
      </TabsContent>

      <TabsContent value="claude-desktop" className="space-y-3 pt-2">
        {step(
          t(
            'mcp.connect.claudeDesktop.step',
            'In Claude Desktop open Settings, Connectors, Add custom connector, and paste this address. It opens the sign-in page.'
          )
        )}
        <SnippetBlock label={t('mcp.connect.address', 'Address')} code={endpoint} />
      </TabsContent>

      <TabsContent value="remote" className="space-y-5 pt-2">
        {step(
          t(
            'mcp.connect.remote.intro',
            'When the assistant runs in an SSH session, a container or another machine, the browser sign-in cannot return to it. Use one of these.'
          )
        )}
        <section className="space-y-2">
          <h3 className="text-sm font-medium">
            {t('mcp.connect.remote.deviceTitle', '1. Sign in with a code (any client)')}
          </h3>
          {step(
            t(
              'mcp.connect.remote.deviceStep',
              'Run the assistant through this bridge. It prints a code: open {url} on any device where you are signed in, type the code, check where the request came from, and allow it.',
              { url: deviceUrl }
            )
          )}
          <SnippetBlock label={commands} code={s.deviceBridge} />
          <SnippetBlock
            label={t('mcp.connect.remote.deviceConfig', 'As an MCP server entry')}
            code={s.deviceBridgeJson}
          />
          <Link href="/oauth/device" className="text-sm underline underline-offset-4">
            {t('mcp.connect.remote.enterCode', 'Enter a code now')}
          </Link>
        </section>
        <section className="space-y-2">
          <h3 className="text-sm font-medium">
            {t('mcp.connect.remote.pasteTitle', '2. Paste the address back (Claude Code)')}
          </h3>
          {step(
            t(
              'mcp.connect.remote.pasteStep',
              'Claude Code prints the sign-in link instead of opening a browser. Open it on your computer, allow, then copy the address of the page that fails to load (it starts with http://localhost) and paste it into the terminal.'
            )
          )}
          <SnippetBlock label={commands} code={s.claudeCodeRemote} />
        </section>
        <section className="space-y-2">
          <h3 className="text-sm font-medium">
            {t('mcp.connect.remote.sshTitle', '3. Forward the sign-in port over SSH')}
          </h3>
          {step(
            t(
              'mcp.connect.remote.sshStep',
              'Connect with the port forwarded and give the client the same fixed port. The browser on your computer then reaches the client on the server.'
            )
          )}
          <SnippetBlock label={commands} code={s.sshForward} />
        </section>
        <p className="text-muted-foreground text-xs">
          {t(
            'mcp.connect.remote.ci',
            'For CI jobs or containers with nobody at the keyboard, use an API key below and keep it in the job’s secret store, never in a prompt.'
          )}
        </p>
      </TabsContent>
    </Tabs>
  )
}
