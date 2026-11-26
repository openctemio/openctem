import fs from 'node:fs'
import { findLiteralUiText } from './src/lib/__tests__/literal-ui-text.ts'
const b = JSON.parse(fs.readFileSync('../../../i18nweb-batches.json','utf8'))['3']
const only = process.argv[2]
for (const f of Object.keys(b)) {
  if (only && !f.includes(only)) continue
  const src = fs.readFileSync('src/' + f, 'utf8')
  const r = findLiteralUiText(f, src)
  console.log('## ' + f + ' ' + r.length)
  for (const x of r) console.log(x.line, x.kind, JSON.stringify(x.text))
}
