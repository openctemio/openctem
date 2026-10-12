#!/usr/bin/env python3
"""sanitize-notes.py: make generated release text safe to publish.

Reads text on stdin (or the file named by the first argument, rewritten in
place) and:
  - drops raw email addresses ("Name <a@b.c>" loses " <a@b.c>", bare ones go);
  - escapes every @mention in backticks, except "by @login" / "* @login"
    credits that GitHub's generated notes write on purpose. Text already in
    backticks is left alone.

Generated notes copy PR titles and commit subjects verbatim, so "@latest" or
"@types/node" would become a mention that pulls an unrelated account into the
release's Contributors, and author emails would be published
(api/docs/rfcs/RFC-037).
"""
import re
import sys

EMAIL_IN_BRACKETS = re.compile(r" ?<[^<>\s]+@[^<>\s]+\.[^<>\s]+>")
BARE_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}(?![\w-]|\.[\w-])")
MENTION = re.compile(
    r"(?<![\w`/.@-])(?<!by )(?<!\* )@[A-Za-z0-9][\w-]*(?:/[\w.-]+)?(?:@[\w.^~-]+)?"
)
CODE_SPAN = re.compile(r"(`[^`]*`)")


def sanitize(text: str) -> str:
    text = EMAIL_IN_BRACKETS.sub("", text)
    parts = CODE_SPAN.split(text)
    out = []
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) >= 2:
            out.append(part)
            continue
        part = BARE_EMAIL.sub("", part)
        part = MENTION.sub(lambda m: "`" + m.group(0) + "`", part)
        out.append(part)
    return "".join(out)


def main() -> None:
    if len(sys.argv) > 1:
        path = sys.argv[1]
        with open(path, encoding="utf-8") as f:
            text = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(sanitize(text))
    else:
        sys.stdout.write(sanitize(sys.stdin.read()))


if __name__ == "__main__":
    main()
