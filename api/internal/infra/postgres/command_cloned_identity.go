package postgres

// A sensor whose key-bound identity runs in two places at once
// (sensors.identity_cloned_at; docs/architecture/sensors.md, "Key use and
// cloned identities") is handed no new work until an administrator resets
// the flag or re-pairs it. The platform cannot tell which host is the real
// one, so dispatch fails closed: every path that grants a lease (the poll,
// the claim-N, the claim by id, the shared claim) and the heartbeat doorbell
// apply the same predicate. Work the sensor already holds runs to its end;
// its lease and epoch fence the results as for any other holder.

// identityNotClonedPredicate is false while the sensor bound to sensorParam
// is flagged as a cloned identity.
func identityNotClonedPredicate(sensorParam string) string {
	return `NOT EXISTS (SELECT 1 FROM sensors cs WHERE cs.id = ` + sensorParam + `::uuid AND cs.identity_cloned_at IS NOT NULL)`
}
