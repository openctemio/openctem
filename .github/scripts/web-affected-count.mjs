// How many Vitest files a change can reach, counted without `npm ci`.
//
//   node web-affected-count.mjs <base-ref>     (run from the repository root)
//
// Walks the import graph of web/src and web/console/src backwards from the
// changed files and prints the number of test files reached. It over-counts on
// purpose (any import, mocked or dynamic, is an edge): a high count only buys
// an extra shard. Prints a large number when it cannot tell.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, normalize } from 'node:path';

const base = process.argv[2];
const roots = ['web/src', 'web/console/src'];
const alias = [['@console/', 'web/console/src/'], ['@extension/', 'web/src/extension-default/'], ['@/', 'web/src/']];
const exts = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '/index.ts', '/index.tsx', '/index.js'];

const files = [];
const walk = (d) => {
  if (!existsSync(d)) return;
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(tsx?|jsx?|mjs)$/.test(n)) files.push(p);
  }
};
roots.forEach(walk);
const known = new Set(files);

const resolve = (from, spec) => {
  let p;
  const a = alias.find(([k]) => spec.startsWith(k));
  if (a) p = a[1] + spec.slice(a[0].length);
  else if (spec.startsWith('.')) p = normalize(join(dirname(from), spec));
  else return null;
  return exts.map((e) => p + e).find((c) => known.has(c)) ?? null;
};

const importers = new Map(); // file -> files importing it
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  for (const m of src.matchAll(/(?:from|import|mock|require)\s*\(?\s*['"]([^'"]+)['"]/g)) {
    const t = resolve(f, m[1]);
    if (t) (importers.get(t) ?? importers.set(t, new Set()).get(t)).add(f);
  }
}

const changed = execFileSync('git', ['diff', '--name-only', base, 'HEAD'], { encoding: 'utf8' }).split('\n').filter((f) => known.has(f));
const seen = new Set(changed);
const queue = [...changed];
while (queue.length) {
  for (const i of importers.get(queue.pop()) ?? []) if (!seen.has(i)) { seen.add(i); queue.push(i); }
}
console.log([...seen].filter((f) => /\.test\.tsx?$/.test(f)).length);
