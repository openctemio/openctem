package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Ledger files in the state directory.
const (
	LedgerLogFile  = "ledger.log"
	LedgerLockFile = "ledger.lock"
)

// maxImportTenants bounds one snapshot file.
const maxImportTenants = 100000

// ImportResult is what an import recorded.
type ImportResult struct {
	SnapshotSHA256 string
	Tenants        int
	Entries        int
	Exclusions     int
	Templates      int
}

// ErrLedgerNotEmpty: an import into a ledger that already holds scope needs
// the operator's explicit replace (it can widen the ledger).
var ErrLedgerNotEmpty = errors.New("the ledger already holds scope: an import would replace it and can widen it; pass -replace only to restore after the signer's state was lost")

// ImportLedger is the operator's ceremony (openctem-signer ledger import),
// run while the signer is stopped (it takes the ledger lock): it replaces
// the ledger with a snapshot file written by `server -signer-ledger-export`
// and sets the default mode to enforce. Into a ledger that already holds
// scope it imports only with replace.
func ImportLedger(stateDir string, raw []byte, replace bool, now time.Time) (ImportResult, error) {
	var res ImportResult
	var exp jobsign.LedgerExport
	if err := strictUnmarshal(raw, &exp); err != nil {
		return res, fmt.Errorf("snapshot: %w", err)
	}
	if exp.Kind != jobsign.SnapshotKind {
		return res, fmt.Errorf("snapshot: kind must be %s", jobsign.SnapshotKind)
	}
	if len(exp.Tenants) > maxImportTenants {
		return res, fmt.Errorf("snapshot: more than %d organizations", maxImportTenants)
	}
	seen := map[string]bool{}
	for i, t := range exp.Tenants {
		if r := validateSnapshot(t); r != nil {
			return res, fmt.Errorf("snapshot: organization %d: %s", i, r.detail)
		}
		if seen[t.TenantID] {
			return res, fmt.Errorf("snapshot: organization %s listed twice", t.TenantID)
		}
		seen[t.TenantID] = true
	}
	lock, err := lockFile(filepath.Join(stateDir, LedgerLockFile))
	if err != nil {
		return res, err
	}
	defer func() { _ = lock.Close() }()
	l, err := openLedgerLocked(filepath.Join(stateDir, LedgerLogFile), false, now)
	if err != nil {
		return res, err
	}
	defer func() { _ = l.log.close() }()
	for _, t := range l.tenants {
		if !t.empty() && !replace {
			return res, ErrLedgerNotEmpty
		}
	}
	sum := sha256.Sum256(raw)
	res.SnapshotSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	if err := l.log.append(&LedgerRecord{Time: now.UTC(), Kind: recordImport, DefaultMode: jobsign.LedgerEnforce,
		SnapshotSHA256: res.SnapshotSHA256}); err != nil {
		return res, err
	}
	for _, t := range exp.Tenants {
		ops := make([]jobsign.LedgerOp, 0, len(t.Entries)+len(t.Exclusions))
		for _, e := range t.Entries {
			if jobsign.Expired(e.ExpiresAt, now) {
				continue
			}
			e := e
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpPutEntry, Entry: &e})
			res.Entries++
		}
		for _, x := range t.Exclusions {
			x := x
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: &x})
			res.Exclusions++
		}
		for _, tpl := range t.Templates {
			tpl := tpl
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpPutTemplate, Template: &tpl})
			res.Templates++
		}
		if err := l.log.append(&LedgerRecord{Time: now.UTC(), Kind: recordImport, TenantID: t.TenantID, Ops: ops}); err != nil {
			return res, err
		}
		res.Tenants++
	}
	return res, nil
}

// ReadLedger replays a ledger.log (read only, no lock) and returns its
// content as a snapshot file and its default mode.
func ReadLedger(r io.Reader, now time.Time) (jobsign.LedgerExport, string, error) {
	l := &Ledger{tenants: map[string]*tenantLedger{}}
	_, _, err := verifyChain(r, "ledger", maxLedgerLine, func(line []byte) error {
		var rec LedgerRecord
		if err := strictUnmarshal(line, &rec); err != nil {
			return err
		}
		return l.replay(rec)
	})
	if err != nil {
		return jobsign.LedgerExport{}, "", err
	}
	out := jobsign.LedgerExport{Kind: jobsign.SnapshotKind, CreatedAt: now.UTC(), Tenants: []jobsign.LedgerSnapshot{}}
	for _, id := range sortedKeys(l.tenants) {
		t := l.tenants[id]
		if t.empty() {
			continue
		}
		s := jobsign.LedgerSnapshot{TenantID: id, Entries: []jobsign.LedgerEntry{}, Exclusions: []jobsign.LedgerExclusion{}}
		for _, k := range sortedKeys(t.entries) {
			s.Entries = append(s.Entries, t.entries[k])
		}
		for _, k := range sortedKeys(t.exclusions) {
			s.Exclusions = append(s.Exclusions, t.exclusions[k])
		}
		for _, k := range sortedKeys(t.templates) {
			s.Templates = append(s.Templates, t.templates[k])
		}
		out.Tenants = append(out.Tenants, s)
	}
	sort.Slice(out.Tenants, func(i, j int) bool { return out.Tenants[i].TenantID < out.Tenants[j].TenantID })
	return out, l.defaultMode, nil
}
