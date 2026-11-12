#!/usr/bin/env bash
# Cross-tenant job isolation gate (api/docs/architecture/sensors.md, "Tenant
# isolation of jobs"): runs the named DB-backed tests that prove a sensor,
# member or token of one organization can never claim, read, change or learn
# of another organization's jobs, and fails unless EVERY named test ran and
# passed. A renamed, deleted, skipped or filtered-out test fails the gate as
# surely as a failing one. These tests are never quarantined.
#
# Run from api/ with DATABASE_URL (and OPENCTEM_TEST_DB_REQUIRED=1) set.
# Usage: cross-tenant-gate.sh [extra go test flags]
set -euo pipefail

# package -> the tests it must pass (top-level names).
declare -A gate=(
	[./internal/infra/http/routes/]="
		TestCrossTenantJobs_ClaimPaths
		TestCrossTenantJobs_CommandRoutes
		TestCrossTenantJobs_TaskSecretsOfAnotherTenant
		TestCrossTenantJobs_SharedSensorOnlyHeldJobs
		TestCrossTenantJobs_ReportIDsArePerSensor
		TestCrossTenantJobs_HeartbeatLeaksNothing
		TestCrossTenantJobs_RelayedRequestMustBeTheRoutesSensor
		TestSensorV2Control_CommandIsolation
		TestSensorV2Control_SuppressionsOwnTenantOnly
		TestTaskSecrets_TenantIsolation
		TestSharedResults_BoundToCommandTenant
		TestSharedResults_RefusedForJobNotHeld
		TestOrganizationSensor_CannotPostSharedJobResults
		TestOrganizationSensor_NeverReceivesSharedJob
		TestSharedClaim_V2StepsOnlyForHeldJobsInTheirOrganization
		TestSensorContentV2_DesiredPacksIndexFilesAndIsolation
		TestSensorContentV2_SharedSensorReadsPlatformPacksOnly
		TestCommandLogs_ReadByCommandID_DB
	"
	[./internal/app/sensorpairing/]="
		TestEnrollmentToken_TenantIsolation_DB
		TestEnrollmentToken_NeverUsedAsTheOtherKind_DB
		TestInstanceEnrollment_RefusedUniformly_DB
	"
)

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
status=0
for pkg in "${!gate[@]}"; do
	names=(${gate[$pkg]})
	run="^($(IFS='|'; echo "${names[*]}"))\$"
	if ! go test -count=1 -json -run "$run" "$@" "$pkg" >"$out"; then
		status=1
	fi
	for n in "${names[@]}"; do
		got="$(jq -r --arg n "$n" 'select(.Test == $n and (.Action == "pass" or .Action == "fail" or .Action == "skip")) | .Action' "$out" | tail -n 1)"
		if [ "$got" != pass ]; then
			echo "::error::cross-tenant gate: $pkg $n: ${got:-did not run}"
			jq -r --arg n "$n" 'select(.Test != null and (.Test == $n or (.Test | startswith($n + "/"))) and .Action == "output") | .Output' "$out" | tail -n 40
			status=1
		else
			echo "ok   $n"
		fi
	done
done
exit "$status"
