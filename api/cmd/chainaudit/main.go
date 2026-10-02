// Command chainaudit recomputes every audit_log_chain row against live data and
// classifies why it does or does not verify.
//
// It exists because "the chain reports 80 breaks" is not actionable on its own.
// Rebaselining a tamper-evident chain re-signs whatever is there, so it erases
// evidence as readily as it clears noise. Before doing that we have to show that
// every break is explained by a known defect and none is an unexplained
// mismatch.
//
// The classification itself lives in internal/app/audit/chainclassify, which
// the platform admin console's "Rebaseline audit chain" action runs too, so the
// server refuses exactly the rows this tool reports as UNEXPLAINED. See that
// package for what each class means.
package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify"
)

type row struct {
	auditLogID string
	position   int
	prevHash   string
	hash       string
	tenantID   string
	action     string
	resType    string
	resID      sql.NullString
	result     string
	loggedAt   time.Time
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL required")
		os.Exit(2)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// Order by tenant then position: the chain is per-tenant, and prev_hash only
	// means anything within one tenant's sequence.
	// c.tenant_id, not l.tenant_id: the chain is keyed by the CHAIN row's
	// tenant. Since the system chain landed (api#414), tenant-less audit rows
	// (every auth.login/failed) are chained under the all-Fs sentinel while
	// audit_logs.tenant_id stays NULL — scanning l.tenant_id crashes on the
	// first system entry, which means this tool broke the moment the system
	// chain gained its first row. l.tenant_id was only ever a proxy for the
	// chain key anyway.
	rows, err := db.Query(`
		SELECT c.audit_log_id, c.chain_position, c.prev_hash, c.hash,
		       c.tenant_id, l.action, l.resource_type, l.resource_id, l.result, l.logged_at
		FROM audit_log_chain c
		JOIN audit_logs l ON l.id = c.audit_log_id
		ORDER BY c.tenant_id, c.chain_position`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query:", err)
		os.Exit(1)
	}
	defer func() { _ = rows.Close() }()

	var (
		total, verifies, legacy, preReduction, unexplained int
		unexplainedRows                                    []row
		recovered                                          []string
		perTenant                                          = map[string][4]int{}
	)

	for rows.Next() {
		var r row
		if err := rows.Scan(&r.auditLogID, &r.position, &r.prevHash, &r.hash,
			&r.tenantID, &r.action, &r.resType, &r.resID, &r.result, &r.loggedAt); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		total++

		res := chainclassify.Classify(chainclassify.Row{
			AuditLogID:   r.auditLogID,
			Position:     int64(r.position),
			PrevHash:     r.prevHash,
			Hash:         r.hash,
			Action:       r.action,
			ResourceType: r.resType,
			ResourceID:   r.resID.String,
			Result:       r.result,
			LoggedAt:     r.loggedAt,
		})

		c := perTenant[r.tenantID]

		switch res.Class {
		case chainclassify.Verifies:
			verifies++
			c[0]++
		case chainclassify.LegacyTruncate:
			legacy++
			c[1]++
		case chainclassify.PreHashReduction:
			preReduction++
			c[2]++
			recovered = append(recovered, fmt.Sprintf("pos=%d offset=%+dns", r.position, res.OffsetNS))
		default:
			unexplained++
			c[3]++
			unexplainedRows = append(unexplainedRows, r)
		}
		perTenant[r.tenantID] = c
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "rows:", err)
		os.Exit(1)
	}

	fmt.Printf("chain rows            : %d\n", total)
	fmt.Printf("  verifies now        : %d\n", verifies)
	fmt.Printf("  legacy truncate bug : %d\n", legacy)
	fmt.Printf("  pre-#79 nanosecond  : %d  (exact original recovered by brute force)\n", preReduction)
	fmt.Printf("  UNEXPLAINED         : %d\n", unexplained)
	fmt.Println()
	fmt.Println("per tenant  (verifies / legacy / pre-79 / unexplained)")
	for t, c := range perTenant {
		fmt.Printf("  %s   %3d / %3d / %3d / %3d\n", t, c[0], c[1], c[2], c[3])
	}

	if unexplained > 0 {
		fmt.Println("\nUNEXPLAINED ROWS — these are NOT accounted for by the known defect:")
		for _, r := range unexplainedRows {
			fmt.Printf("  tenant=%s pos=%d audit_log=%s action=%s logged_at=%s\n",
				r.tenantID, r.position, r.auditLogID, r.action, r.loggedAt.Format(time.RFC3339Nano))
		}
		fmt.Println("\nDo NOT rebaseline until each of these is explained.")
		os.Exit(1)
	}
	fmt.Printf("\nrecovered nanosecond offsets: %v\n", recovered)
	fmt.Println("Every break is explained. None is an unexplained mismatch.")
}
