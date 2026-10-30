// Tests for scripts/i18n-json.mjs: the key-wise three-way merge and the git
// merge driver end to end in a scratch repository.
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { format, merge3, parse, renderWithConflicts } from './i18n-json.mjs'

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'i18n-json.mjs')

describe('merge3', () => {
  const base = { 'a.one': '1', 'a.two': '2', 'a.three': '3' }

  it('keeps keys added on both sides next to each other', () => {
    const ours = { ...base, 'a.four': '4' }
    const theirs = { ...base, 'a.five': '5' }
    const { merged, conflicts } = merge3(base, ours, theirs)
    expect(conflicts).toEqual([])
    expect(merged).toEqual({ ...base, 'a.four': '4', 'a.five': '5' })
  })

  it('takes the side that changed or deleted a key the other left alone', () => {
    const ours = { ...base, 'a.one': 'one' }
    const theirs = { 'a.one': '1', 'a.two': '2' } // deleted a.three
    const { merged, conflicts } = merge3(base, ours, theirs)
    expect(conflicts).toEqual([])
    expect(merged).toEqual({ 'a.one': 'one', 'a.two': '2' })
  })

  it('keeps one copy of the same change made on both sides', () => {
    const both = { ...base, 'a.two': 'two', 'a.new': 'n' }
    expect(merge3(base, both, both)).toEqual({ merged: both, conflicts: [] })
  })

  it('reports a key both sides changed differently, and only that key', () => {
    const ours = { ...base, 'a.two': 'ours', 'a.x': 'x' }
    const theirs = { ...base, 'a.two': 'theirs', 'a.y': 'y' }
    const { merged, conflicts } = merge3(base, ours, theirs)
    expect(conflicts).toEqual([['a.two', 'ours', 'theirs']])
    expect(merged).toEqual({ 'a.one': '1', 'a.three': '3', 'a.x': 'x', 'a.y': 'y' })
  })

  it('treats a key changed on one side and deleted on the other as a conflict', () => {
    const ours = { ...base, 'a.two': 'changed' }
    const theirs = { 'a.one': '1', 'a.three': '3' }
    expect(merge3(base, ours, theirs).conflicts).toEqual([['a.two', 'changed', undefined]])
  })
})

describe('format and parse', () => {
  it('writes keys in code-unit order with a final newline', () => {
    expect(format({ 'b.a': '1', 'B.a': '2', 'a.b': '3' })).toBe(
      '{\n  "B.a": "2",\n  "a.b": "3",\n  "b.a": "1"\n}\n'
    )
  })

  it('accepts only a flat object of strings', () => {
    expect(parse('{"a.b":"c"}')).toEqual({ 'a.b': 'c' })
    expect(parse('{"a":{"b":"c"}}')).toBeNull()
    expect(parse('[]')).toBeNull()
    expect(parse('{"a": 1}')).toBeNull()
    expect(parse('<<<<<<< ours')).toBeNull()
  })

  it('renders a conflict with markers around the key and is not valid JSON', () => {
    const text = renderWithConflicts({ 'a.a': '1', 'a.c': '3' }, [['a.b', 'x', 'y']], 'en/a.json')
    expect(text).toBe(
      [
        '{',
        '  "a.a": "1",',
        '<<<<<<< ours',
        '  "a.b": "x",',
        '=======',
        '  "a.b": "y",',
        '>>>>>>> theirs (en/a.json)',
        '  "a.c": "3"',
        '}',
        '',
      ].join('\n')
    )
    expect(parse(text)).toBeNull()
  })
})

describe('git merge driver', () => {
  const git = (cwd, ...args) =>
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', ...args], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })

  function repo() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'i18n-merge-'))
    git(dir, 'init', '-q', '-b', 'main')
    git(dir, 'config', 'merge.i18n-json.driver', `node ${JSON.stringify(SCRIPT)} merge %O %A %B %P`)
    fs.writeFileSync(path.join(dir, '.gitattributes'), '*.json merge=i18n-json\n')
    fs.writeFileSync(path.join(dir, 'a.json'), format({ 'a.one': '1', 'a.two': '2' }))
    git(dir, 'add', '.')
    git(dir, 'commit', '-qm', 'base')
    return dir
  }

  function branch(dir, name, from, obj) {
    git(dir, 'checkout', '-q', '-b', name, from)
    fs.writeFileSync(path.join(dir, 'a.json'), format(obj))
    git(dir, 'commit', '-qam', name)
  }

  it('merges two branches that add adjacent keys, which a line merge cannot', () => {
    const dir = repo()
    branch(dir, 'left', 'main', { 'a.one': '1', 'a.onf': 'left', 'a.two': '2' })
    branch(dir, 'right', 'main', { 'a.one': '1', 'a.ong': 'right', 'a.two': '2' })
    git(dir, 'merge', '-q', '--no-edit', 'left')
    expect(JSON.parse(fs.readFileSync(path.join(dir, 'a.json'), 'utf8'))).toEqual({
      'a.one': '1',
      'a.onf': 'left',
      'a.ong': 'right',
      'a.two': '2',
    })
    // Without the driver, git's line merge conflicts on the same input.
    const plain = repo()
    fs.writeFileSync(path.join(plain, '.gitattributes'), '')
    git(plain, 'commit', '-qam', 'no driver')
    branch(plain, 'left', 'main', { 'a.one': '1', 'a.onf': 'left', 'a.two': '2' })
    branch(plain, 'right', 'main', { 'a.one': '1', 'a.ong': 'right', 'a.two': '2' })
    expect(() => git(plain, 'merge', '-q', '--no-edit', 'left')).toThrow()
  })

  it('leaves a real conflict for a person, with markers, and git reports it', () => {
    const dir = repo()
    branch(dir, 'left', 'main', { 'a.one': 'left', 'a.two': '2' })
    branch(dir, 'right', 'main', { 'a.one': 'right', 'a.two': '2' })
    expect(() => git(dir, 'merge', '-q', '--no-edit', 'left')).toThrow()
    expect(git(dir, 'diff', '--name-only', '--diff-filter=U').trim()).toBe('a.json')
    const text = fs.readFileSync(path.join(dir, 'a.json'), 'utf8')
    expect(text).toContain('<<<<<<< ours\n  "a.one": "right",\n=======\n  "a.one": "left",')
  })
})
