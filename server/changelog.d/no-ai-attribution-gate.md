### Added: a CI check refuses AI attribution in commits and pull requests

- The new "No AI attribution" check fails a pull request (and a merge queue group) when a commit message, the pull request title or its body carries a `Co-Authored-By` trailer naming an AI assistant, a session trailer or link, or a "Generated with" line. The local `commit-msg` hook only runs in clones where hooks are enabled; the check runs on the server for everyone.
- The hook and the check share one script, `.github/scripts/check-attribution.sh`, with a self-test.
