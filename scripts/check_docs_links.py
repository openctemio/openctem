#!/usr/bin/env python3
"""Check documentation links in code: docs.openctem.io pages and GitHub file links.

Usage:
  python3 scripts/check_docs_links.py --docs DOCS_CHECKOUT [--repo NAME]
      [--fetch-other] [PATH ...]

Scans source files under each PATH (default: the current directory) for
  - https://docs.openctem.io/<page>[#anchor]: the page must exist in the
    openctemio/docs checkout given with --docs (Jekyll, `permalink: pretty`:
    foo/bar.md is /foo/bar/, foo/index.md is /foo/) and the anchor must be a
    heading slug or an explicit id on that page;
  - https://github.com/openctemio/<repo>/(blob|tree)/<branch>/<path>[#anchor]
    and https://raw.githubusercontent.com/openctemio/<repo>/<branch>/<path>:
    the file must exist on that branch and a Markdown anchor must exist in it.
    Links into this repository (--repo, default: the name of the current
    directory) are checked against the working tree. Other repositories are
    cloned shallowly with --fetch-other; without it they are skipped with a
    warning.

Tests, test data, node_modules and generated files are skipped. A URL that is
only a prefix (followed by `${`, `%s`, `{{` or `+`) has only its page
checked. A line carrying the marker `docs-links: ignore` is skipped.
Standard library only.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

EXTS = {
    ".go", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".sh", ".yml", ".yaml",
    ".json", ".toml", ".tmpl", ".tpl", ".txt", ".html", ".md", ".rb", ".rs",
}
NAMES = {"Dockerfile", "Makefile", "justfile"}
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "testdata", "__tests__", "tests", "test",
    "e2e", "fixtures", "_site", ".next", "dist", "build", "coverage", "generated",
    "changelog.d",
}
SKIP_FILE = re.compile(r"(_test\.go|\.test\.[cm]?[jt]sx?|\.spec\.[cm]?[jt]sx?|_test\.py|CHANGELOG\.md)$")
IGNORE = "docs-links: ignore"

END = r"[^\s\"'`<>()\[\]{}\\,|$%*]"
# Not followed by more of a host name, a port or credentials.
DOCS_URL = re.compile(r"https://docs\.openctem\.io(?![\w@:-]|\.\w)((?:/" + END + r"*)?)")
GH_URL = re.compile(
    r"https://github\.com/openctemio/([\w.-]+)/(blob|tree)/([\w.-]+)/(" + END + r"*)"
)
RAW_URL = re.compile(r"https://raw\.githubusercontent\.com/openctemio/([\w.-]+)/([\w.-]+)/(" + END + r"*)")
FENCE = re.compile(r"^\s*(```|~~~)")
FRONT = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)


def slugify(heading):
    """GitHub/kramdown-style anchor for a heading (as scripts/docs_check.py)."""
    text = re.sub(r"<[^>]+>", "", heading).strip().lower()
    text = re.sub(r"[`*_~]", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_anchor_cache = {}


def anchors_of(path):
    """Heading slugs and explicit ids of a Markdown file."""
    if path in _anchor_cache:
        return _anchor_cache[path]
    found, seen, in_fence = set(), {}, False
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        text = ""
    text = FRONT.sub("", text)
    for line in text.splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            heading = m.group(1)
            explicit = re.search(r"\{:?\s*#([\w-]+)\s*\}\s*$", heading)
            if explicit:
                found.add(explicit.group(1))
                heading = heading[: explicit.start()]
            slug = slugify(heading)
            n = seen.get(slug, 0)
            seen[slug] = n + 1
            found.add(slug if n == 0 else f"{slug}-{n}")
        for a in re.findall(r"""(?:id|name)=["']([^"']+)["']""", line):
            found.add(a)
        for a in re.findall(r"\{:\s*#([\w-]+)\s*\}", line):
            found.add(a)
    _anchor_cache[path] = found
    return found


def docs_index(root):
    """URL path -> source file for every page of the Jekyll docs site."""
    pages = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith((".", "_")) and d not in {"node_modules", "vendor", "scripts"}]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if name.endswith((".md", ".html")):
                try:
                    with open(full, encoding="utf-8") as fh:
                        head = fh.read(4096)
                except (OSError, UnicodeDecodeError):
                    continue
                front = FRONT.match(head)
                if not front:
                    continue  # Jekyll does not render a page without front matter
                link = re.search(r"^permalink:\s*[\"']?([^\"'\s]+)", front.group(1), re.M)
                if link:
                    url = link.group(1)
                else:
                    stem = rel.rsplit(".", 1)[0]
                    if stem == "index":
                        url = "/"
                    elif stem.endswith("/index"):
                        url = "/" + stem[: -len("index")]
                    else:
                        url = "/" + stem + "/"
                pages[url] = full
            else:
                pages["/" + rel] = None  # a static file
    return pages


class Repos:
    """Files of openctemio repositories at a branch."""

    def __init__(self, self_name, self_root, fetch):
        self.self_name, self.self_root, self.fetch = self_name, self_root, fetch
        self.self_branch = self._branch(self_root)
        self.clones = {}
        self.tmp = None

    @staticmethod
    def _branch(root):
        try:
            out = subprocess.run(["git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD"],
                                 capture_output=True, text=True, check=True).stdout.strip()
            return out
        except (OSError, subprocess.CalledProcessError):
            return ""

    def root(self, repo, ref):
        """A directory with the repository at ref, '' if it does not exist, None if unchecked."""
        if repo == self.self_name:
            return self.self_root
        key = (repo, ref)
        if key not in self.clones:
            if not self.fetch:
                self.clones[key] = None
            else:
                if self.tmp is None:
                    self.tmp = tempfile.mkdtemp(prefix="docs-links-")
                dest = os.path.join(self.tmp, f"{repo}@{ref}")
                env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
                ok = True
                # init + fetch works for a branch, a tag and a commit id.
                for cmd in (["git", "init", "-q", dest],
                            ["git", "-C", dest, "fetch", "-q", "--depth", "1",
                             f"https://github.com/openctemio/{repo}.git", ref],
                            ["git", "-C", dest, "checkout", "-q", "FETCH_HEAD"]):
                    if ok:
                        ok = subprocess.run(cmd, capture_output=True, text=True, env=env).returncode == 0
                self.clones[key] = dest if ok else ""
        return self.clones[key]


def source_files(paths, exclude=()):
    exclude = {os.path.realpath(e) for e in exclude}
    for top in paths:
        if os.path.isfile(top):
            yield top
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in SKIP_DIRS and os.path.realpath(os.path.join(dirpath, d)) not in exclude
            )
            for name in sorted(filenames):
                if SKIP_FILE.search(name):
                    continue
                if os.path.splitext(name)[1] in EXTS or name in NAMES or name.startswith("Dockerfile"):
                    yield os.path.join(dirpath, name)


def split_anchor(url):
    url = url.rstrip(".:;")
    path, _, anchor = url.partition("#")
    return path.split("?")[0], anchor


def check_docs(path, anchor, prefix, pages):
    if not path:
        path = "/"
    candidates = [path, path + "/"] if not path.endswith("/") else [path]
    for c in candidates:
        if c in pages:
            if anchor and not prefix and pages[c] and anchor not in anchors_of(pages[c]):
                return f"no anchor #{anchor} on https://docs.openctem.io{c}"
            if c != path and c.endswith("/") and pages[c]:
                return f"use the canonical URL https://docs.openctem.io{c} (trailing slash)"
            return None
    return "no such page on docs.openctem.io"


def check_repo_file(repos, repo, ref, fpath, anchor, prefix):
    root = repos.root(repo, ref)
    if root is None:
        return None, f"skipped (not fetched): github.com/openctemio/{repo}@{ref}"
    if root == "":
        return f"ref {ref} of openctemio/{repo} not found", None
    if repo == repos.self_name and repos.self_branch not in ("", "HEAD", ref):
        note = f"checked against the working tree ({repos.self_branch}), not {ref}"
    else:
        note = None
    target = os.path.join(root, fpath)
    if prefix:
        return None, note
    if not os.path.exists(target):
        return f"no such file in openctemio/{repo}@{ref}", note
    if anchor and os.path.isfile(target):
        if re.fullmatch(r"L\d+(-L\d+)?", anchor):
            return None, note
        if target.endswith((".md", ".markdown")) and anchor not in anchors_of(target):
            return f"no anchor #{anchor} in {fpath}", note
    return None, note


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--docs", required=True, help="checkout of openctemio/docs")
    ap.add_argument("--repo", help="name of this repository (default: current directory name)")
    ap.add_argument("--fetch-other", action="store_true", help="clone other openctemio repositories to check their links")
    ap.add_argument("paths", nargs="*", default=["."])
    args = ap.parse_args(argv)

    root = os.getcwd()
    pages = docs_index(args.docs)
    if not pages:
        print(f"check_docs_links: no pages found under {args.docs}", file=sys.stderr)
        return 2
    repos = Repos(args.repo or os.path.basename(root), root, args.fetch_other)
    errors, warnings, count = [], set(), 0
    for f in source_files(args.paths, exclude=[args.docs]):
        try:
            with open(f, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(lines, 1):
            if IGNORE in line or ("docs.openctem.io" not in line and "/openctemio/" not in line):
                continue
            where = f"{os.path.relpath(f, root)}:{lineno}"
            for m in DOCS_URL.finditer(line):
                url = m.group(0)
                nxt = line[m.end(): m.end() + 2]
                prefix = nxt.startswith(("${", "%", "{{", "+", "$")) or url.endswith("#")
                count += 1
                path, anchor = split_anchor(m.group(1))
                err = check_docs(path, anchor, prefix, pages)
                if err:
                    errors.append(f"{where}: {url}: {err}")
            for m in GH_URL.finditer(line):
                count += 1
                repo, _kind, ref, rest = m.groups()
                fpath, anchor = split_anchor(rest)
                prefix = line[m.end(): m.end() + 2].startswith(("${", "%", "{{", "+", "$"))
                err, note = check_repo_file(repos, repo, ref, fpath.rstrip("/"), anchor, prefix)
                if err:
                    errors.append(f"{where}: {m.group(0)}: {err}")
                if note:
                    warnings.add(note)
            for m in RAW_URL.finditer(line):
                count += 1
                repo, ref, rest = m.groups()
                fpath, _ = split_anchor(rest)
                prefix = line[m.end(): m.end() + 2].startswith(("${", "%", "{{", "+", "$"))
                err, note = check_repo_file(repos, repo, ref, fpath, "", prefix)
                if err:
                    errors.append(f"{where}: {m.group(0)}: {err}")
                if note:
                    warnings.add(note)
    for w in sorted(warnings):
        print(f"warning: {w}", file=sys.stderr)
    for e in errors:
        print(e)
    print(f"check_docs_links: {count} links, {len(errors)} broken", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
