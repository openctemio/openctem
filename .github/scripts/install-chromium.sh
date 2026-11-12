#!/usr/bin/env bash
# Install Playwright's Chromium for a CI job without depending on the Ubuntu
# package mirrors when the system libraries are already on the runner image.
#
#   install-chromium.sh [--only-shell]     (run from web/)
#
# 1. download the browser build (Playwright CDN, no apt);
# 2. if Chromium already starts, stop: nothing to install;
# 3. otherwise install the libraries with apt, retried with back-off;
# 4. fail only when Chromium still cannot start, and say why.
set -uo pipefail

shell_flag=()
if [ "${1:-}" = "--only-shell" ]; then
  shell_flag=(--only-shell)
fi

chromium_starts() {
  node -e "
    const { chromium } = require('@playwright/test');
    chromium.launch().then((b) => b.close()).then(() => process.exit(0), (e) => {
      console.error(String(e.message || e).split('\n').slice(0, 6).join('\n'));
      process.exit(1);
    });
  "
}

npx playwright install "${shell_flag[@]}" chromium || exit 1

if chromium_starts; then
  echo "Chromium starts with the libraries already on this runner: skipping the apt install."
  exit 0
fi

echo "Chromium does not start yet: installing its system libraries with apt."
echo 'Acquire::Retries "5";' | sudo tee /etc/apt/apt.conf.d/80-ci-retries >/dev/null || true

delays=(20 40 60 0)
for i in 0 1 2 3; do
  echo "apt attempt $((i + 1)) of 4"
  if npx playwright install-deps chromium; then
    break
  fi
  if [ "${delays[$i]}" -gt 0 ]; then
    echo "apt failed; retrying in ${delays[$i]}s"
    sleep "${delays[$i]}"
  fi
done

if chromium_starts; then
  echo "Chromium starts after the apt install."
  exit 0
fi

echo "::error::Chromium cannot start: its system libraries are missing and the Ubuntu package mirrors (archive.ubuntu.com, security.ubuntu.com) could not be reached to install them. This is a runner or network outage, not a test failure: re-run the job once the mirrors answer."
exit 1
