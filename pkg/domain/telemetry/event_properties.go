// Package telemetry defines the wire-format constants agents and the
// correlator share when reading runtime_telemetry_events.properties.
//
// There is no entity / repository here — the table is owned by
// runtime_telemetry_handler — but the JSON keys inside `properties`
// are a contract: an agent emits "remote_ip", the correlator reads
// "remote_ip". Centralising the names here keeps the two sides from
// drifting.
//
// Changing any value here is a WIRE-FORMAT BREAK. Old agents still
// pushing the previous key will silently produce events the
// correlator no longer reads, so any rename needs a deprecation
// window.
package telemetry

// Property keys recognised by the correlator (see
// internal/app/ioc/correlator.go — ExtractCandidates).
//
// Grouped by event_type the key most often appears on, for human
// readability — but the correlator does not enforce per-event-type
// restrictions. An agent is free to emit `remote_ip` on any event.
const (
	// Network — network_connect events
	PropRemoteIP     = "remote_ip"
	PropSourceIP     = "source_ip"
	PropRemoteDomain = "remote_domain"
	PropRemoteURL    = "remote_url"

	// DNS — dns_query events
	PropQueryName = "query_name"

	// Process — process_start events
	PropImageHash   = "image_hash"
	PropProcessName = "process_name"

	// File — file_write / file_delete events
	PropFileHash = "file_hash"

	// HTTP — http_request events
	PropURL       = "url"
	PropUserAgent = "user_agent"
)
