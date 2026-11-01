/**
 * Copy-paste setup for the MCP clients people use, built for this
 * instance's endpoint. Client and command names are what each client's own
 * documentation uses; they are not translated.
 */

export type ClientId =
  'claude-code' | 'codex' | 'gemini' | 'vscode' | 'cursor' | 'claude-desktop' | 'remote'

export const CLIENT_IDS: ClientId[] = [
  'claude-code',
  'codex',
  'gemini',
  'vscode',
  'cursor',
  'claude-desktop',
  'remote',
]

/** Display names of the clients (proper names, never translated). */
export const CLIENT_NAMES: Record<Exclude<ClientId, 'remote'>, string> = {
  'claude-code': 'Claude Code',
  codex: 'Codex CLI',
  gemini: 'Gemini CLI',
  vscode: 'VS Code',
  cursor: 'Cursor',
  'claude-desktop': 'Claude Desktop',
}

/** The platform's terminal client id for the device code sign-in. */
export const TERMINAL_CLIENT_ID = 'octc_terminal'

/** A fixed loopback port for clients that need one (SSH forwarding). */
export const CALLBACK_PORT = 33418

const SERVER = 'openctem'

export interface Snippets {
  claudeCode: string
  claudeCodeRemote: string
  codexCli: string
  codexToml: string
  geminiJson: string
  vscodeJson: string
  cursorJson: string
  deviceBridge: string
  deviceBridgeJson: string
  sshForward: string
}

/** Every snippet for the MCP endpoint at url (https://host/api/v1/mcp). */
export function buildSnippets(url: string): Snippets {
  const json = (v: unknown) => JSON.stringify(v, null, 2)
  const bridgeArgs = [
    '-y',
    'mcp-remote',
    url,
    '--device-code',
    '--static-oauth-client-info',
    JSON.stringify({ client_id: TERMINAL_CLIENT_ID }),
  ]
  return {
    claudeCode: [
      `claude mcp add --transport http ${SERVER} ${url}`,
      `claude mcp login ${SERVER}`,
    ].join('\n'),
    claudeCodeRemote: `claude mcp login ${SERVER} --no-browser`,
    codexCli: [`codex mcp add ${SERVER} --url ${url}`, `codex mcp login ${SERVER}`].join('\n'),
    codexToml: [`[mcp_servers.${SERVER}]`, `url = "${url}"`].join('\n'),
    geminiJson: json({
      mcpServers: {
        [SERVER]: {
          httpUrl: url,
          oauth: {
            enabled: true,
            clientId: 'octc_...',
            redirectUri: `http://localhost:${CALLBACK_PORT}/oauth/callback`,
          },
        },
      },
    }),
    vscodeJson: json({ servers: { [SERVER]: { type: 'http', url } } }),
    cursorJson: json({ mcpServers: { [SERVER]: { url } } }),
    deviceBridge: `npx ${bridgeArgs.slice(0, 5).join(' ')} '${bridgeArgs[5]}'`,
    deviceBridgeJson: json({ mcpServers: { [SERVER]: { command: 'npx', args: bridgeArgs } } }),
    sshForward: [
      `ssh -L ${CALLBACK_PORT}:127.0.0.1:${CALLBACK_PORT} you@your-server`,
      `claude mcp add --transport http --callback-port ${CALLBACK_PORT} ${SERVER} ${url}`,
      `claude mcp login ${SERVER}`,
    ].join('\n'),
  }
}
