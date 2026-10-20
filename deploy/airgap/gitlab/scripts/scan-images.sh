#!/usr/bin/env bash
# scan-images.sh <mirrored-list>: Trivy scan of every image in the list that
# mirror-images.sh wrote ("<name> <ref> <digest>" lines), by digest. Fails when
# an image has a finding at $TRIVY_SEVERITY (default CRITICAL) with a fix
# available. Reports go to ./trivy-<name>.json for the audit trail.
# In an air gap point Trivy at your registry's copies of its databases:
#   TRIVY_DB_REPOSITORY=registry.example.internal/aquasecurity/trivy-db
#   TRIVY_JAVA_DB_REPOSITORY=registry.example.internal/aquasecurity/trivy-java-db
set -euo pipefail
die() { echo "scan-images: $*" >&2; exit 1; }
{ [ $# -eq 1 ] && [ -r "$1" ]; } || die "usage: scan-images.sh <mirrored-list>"
rc=0
while read -r name ref digest; do
	case "$name" in "" | \#*) continue ;; esac
	img="${ref%:*}@${digest}"
	trivy image --quiet --format json --output "trivy-${name}.json" "$img" || die "trivy could not scan $img"
	if ! trivy image --quiet --skip-db-update --exit-code 1 --ignore-unfixed \
		--severity "${TRIVY_SEVERITY:-CRITICAL}" "$img"; then
		echo "scan-images: $name has ${TRIVY_SEVERITY:-CRITICAL} findings with a fix" >&2
		rc=1
	fi
done <"$1"
exit "$rc"
