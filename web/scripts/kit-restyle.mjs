// Pages do not restyle kit controls (web/docs/ui-style-contract.md, "Sizes"):
// a control's height, width, padding, text size and colour come from the
// shared tokens (src/styles/theme.css) through the kit component
// (src/components/ui) and its variants. This finds, in page and feature code
// (src/app, src/features, console/src), a kit control that gets one of those
// in its className:
//   height h-*, min-h-*, max-h-*; size-*; a fixed width w-<n> on an icon-only
//   size; padding p-*, px-*, py-*, ps-*, pe-*, pt-*, pb-*; a text size
//   (text-xs.. text-9xl, text-[..], the type roles text-cap, text-dense...);
//   a colour (bg-*, text-<colour>).
// Only literal class strings are read (string literals, template text and
// the string arguments of cn(...) and conditionals).
// usage: node scripts/kit-restyle.mjs [--files] [--folders]   (from web/)
// src/components/ui/__tests__/kit-restyle-ratchet.test.ts keeps the count per
// file at or below scripts/kit-restyle-debt.json.
import { readFileSync } from 'node:fs'
import { execSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

export const KIT_CONTROLS = new Set([
  'Button',
  'Input',
  'SelectTrigger',
  'ListSearch',
  'TabsTrigger',
  'Badge',
])

const ICON_SIZES = new Set(['icon', 'icon-sm', 'icon-seg', 'xs'])
const TEXT_SIZES =
  /^text-(xs|sm|base|lg|xl|[2-9]xl|\[.+\]|cap|cap-m|code|dense|body|card-title|section|dialog|page|figure|figure-lead|hero|wall|title|meta|data|kpi)$/
const TEXT_NOT_COLOUR =
  /^text-(left|center|right|start|end|justify|wrap|nowrap|balance|pretty|ellipsis|clip)$/

/** The reason a single utility restyles a kit control, or null. */
export function restyleKind(token, iconSize) {
  // Drop variants (md:, max-md:, hover:, dark:, [&>svg]:...) and the important mark.
  let u = token
  let depth = 0
  let cut = 0
  for (let i = 0; i < u.length; i++) {
    if (u[i] === '[') depth++
    else if (u[i] === ']') depth--
    else if (u[i] === ':' && depth === 0) cut = i + 1
  }
  u = u.slice(cut).replace(/^!|!$/g, '')
  if (u.startsWith('-')) u = u.slice(1)
  if (/^(min-|max-)?h-/.test(u)) return 'height'
  if (/^size-/.test(u)) return 'size'
  if (iconSize && /^(min-|max-)?w-(\d|\[|px$)/.test(u)) return 'width'
  if (/^p[xysetblr]?-/.test(u)) return 'padding'
  if (TEXT_SIZES.test(u)) return 'text size'
  if (/^bg-/.test(u)) return 'colour'
  if (/^text-/.test(u) && !TEXT_NOT_COLOUR.test(u) && !TEXT_SIZES.test(u)) return 'colour'
  return null
}

/** String pieces of a className initializer (literals, templates, cn() args). */
function classStrings(node, out = []) {
  if (!node) return out
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) out.push(node.text)
  else if (ts.isTemplateExpression(node)) {
    out.push(node.head.text)
    for (const s of node.templateSpans) {
      classStrings(s.expression, out)
      out.push(s.literal.text)
    }
  } else ts.forEachChild(node, (c) => classStrings(c, out))
  return out
}

export function findKitRestyles(web) {
  const files = execSync("git ls-files 'src/app/*.tsx' 'src/features/*.tsx' 'console/src/*.tsx'", {
    cwd: web,
    encoding: 'utf8',
  })
    .split('\n')
    .filter((f) => f && !/__tests__|\.test\.tsx$|\.stories\.tsx$/.test(f))

  /** file -> [{ line, control, kinds, classes }] */
  const found = new Map()
  for (const f of files) {
    const src = readFileSync(path.join(web, f), 'utf8')
    if (![...KIT_CONTROLS].some((c) => src.includes(`<${c}`))) continue
    const sf = ts.createSourceFile(f, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
    const visit = (n) => {
      if (ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) {
        const tag = n.tagName.getText(sf)
        if (KIT_CONTROLS.has(tag)) {
          const props = n.attributes.properties
          const attr = (name) =>
            props.find((p) => ts.isJsxAttribute(p) && p.name.getText(sf) === name)
          const size = attr('size')?.initializer
          const iconSize = !!size && ts.isStringLiteral(size) && ICON_SIZES.has(size.text)
          const cn = attr('className')?.initializer
          if (cn) {
            const hits = []
            for (const s of classStrings(cn))
              for (const tok of s.split(/\s+/).filter(Boolean)) {
                const k = restyleKind(tok, iconSize)
                if (k) hits.push([k, tok])
              }
            if (hits.length) {
              const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1
              const list = found.get(f) ?? []
              list.push({
                line,
                control: tag,
                kinds: [...new Set(hits.map((h) => h[0]))],
                classes: hits.map((h) => h[1]),
              })
              found.set(f, list)
            }
          }
        }
      }
      ts.forEachChild(n, visit)
    }
    visit(sf)
  }
  return found
}

/** Count per top folder: src/app/(dashboard)/x -> app/(dashboard)/x, features/x. */
export function folderOf(file) {
  const p = file.split('/')
  if (p[0] === 'console') return `console/${p[2]}/${p[3] ?? ''}`.replace(/\/$/, '')
  if (p[1] === 'features') return `features/${p[2]}`
  return p.slice(1, p[2]?.startsWith('(') ? 4 : 3).join('/')
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const found = findKitRestyles(web)
  let total = 0
  const folders = new Map()
  for (const [f, list] of found) {
    total += list.length
    folders.set(folderOf(f), (folders.get(folderOf(f)) ?? 0) + list.length)
    if (process.argv.includes('--files'))
      for (const h of list)
        console.log(`${f}:${h.line} <${h.control}> ${h.kinds.join(', ')}: ${h.classes.join(' ')}`)
  }
  if (process.argv.includes('--folders'))
    for (const [k, v] of [...folders].sort((a, b) => b[1] - a[1])) console.log(`${v}\t${k}`)
  console.log(`kit controls restyled in page code: ${total} in ${found.size} files`)
}
