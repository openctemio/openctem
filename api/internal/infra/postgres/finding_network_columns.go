package postgres

import (
	"database/sql"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The network columns of the findings table (migration 000326): the port,
// transport and service a finding was observed on, from CTIS Finding.Network.
// Ingest used the port only inside the network-VA fingerprint and dropped it,
// so no stored finding knew its port.
//
// They are not fingerprint inputs. Order matters: findingNetworkColumnsSQL,
// findingNetworkArgs and findingNetworkScan.dests list the columns in the same
// order.
const findingNetworkColumnsSQL = `network_port, network_transport, network_service`

// findingNetworkColumnCount is the number of columns in findingNetworkColumnsSQL.
const findingNetworkColumnCount = 3

func findingNetworkArgs(f *vulnerability.Finding) []any {
	n := f.Network()
	var port sql.NullInt64
	if n.Port > 0 {
		port = sql.NullInt64{Int64: int64(n.Port), Valid: true}
	}
	return []any{port, nullString(n.Transport), nullString(n.Service)}
}

// findingNetworkConflictSQL is the ON CONFLICT ... DO UPDATE part. First
// writer wins, like the enrich path (Finding.enrichNetwork): a stored port is
// kept, a NULL one is filled. A fingerprint that does not include the port can
// cover two ports, and last-writer-wins would flip the stored one per scan.
func findingNetworkConflictSQL() string {
	return `,
			network_transport = CASE WHEN findings.network_port IS NULL OR findings.network_port = EXCLUDED.network_port
				THEN COALESCE(findings.network_transport, EXCLUDED.network_transport) ELSE findings.network_transport END,
			network_service = CASE WHEN findings.network_port IS NULL OR findings.network_port = EXCLUDED.network_port
				THEN COALESCE(findings.network_service, EXCLUDED.network_service) ELSE findings.network_service END,
			network_port = COALESCE(findings.network_port, EXCLUDED.network_port)`
}

// findingNetworkScan receives the network columns of a SELECT.
type findingNetworkScan struct {
	port      sql.NullInt64
	transport sql.NullString
	service   sql.NullString
}

func (s *findingNetworkScan) dests() []any {
	return []any{&s.port, &s.transport, &s.service}
}

func (s *findingNetworkScan) location() vulnerability.NetworkLocation {
	return vulnerability.NetworkLocation{
		Port:      int(s.port.Int64),
		Transport: s.transport.String,
		Service:   s.service.String,
	}
}

// findingNetworkPlaceholders is ", $first, …" for the network columns of a
// hand-numbered single-row INSERT.
func findingNetworkPlaceholders(first int) string {
	out := ""
	for i := 0; i < findingNetworkColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}
