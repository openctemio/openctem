package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/openctem/api/internal/signer"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// maxSnapshotFile bounds a snapshot file read by ledger import.
const maxSnapshotFile = 512 << 20

// ledgerCmd runs `openctem-signer ledger verify|show|import`.
//
//	ledger verify                      check ledger.log's chain and replay it
//	ledger show                        print the ledger as a snapshot file (JSON)
//	ledger import -file F [-replace]   the bootstrap or restore ceremony (signer stopped)
func ledgerCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("ledger: verify, show or import")
	}
	dir := os.Getenv("SIGNER_STATE_DIR")
	if dir == "" {
		return errors.New("SIGNER_STATE_DIR is required")
	}
	switch args[0] {
	case "verify":
		f, err := os.Open(filepath.Join(dir, signer.LedgerLogFile)) // #nosec G304 -- operator-supplied state directory
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		last, n, err := signer.VerifyLedgerLog(f)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "ledger log OK: %d records, head %s\n", n, last)
		return nil
	case "show":
		f, err := os.Open(filepath.Join(dir, signer.LedgerLogFile)) // #nosec G304 -- operator-supplied state directory
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		snap, mode, err := signer.ReadLedger(f, time.Now())
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stderr, "default mode: %s (SIGNER_LEDGER overrides it)\n", mode)
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	case "import":
		return ledgerImport(dir, args[1:], out)
	}
	return fmt.Errorf("ledger: unknown command %q (verify, show, import)", args[0])
}

func ledgerImport(dir string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ledger import", flag.ContinueOnError)
	file := fs.String("file", "", "snapshot file written by `server -signer-ledger-export`")
	replace := fs.Bool("replace", false, "replace a ledger that already holds scope (restore after state loss; can widen it)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("ledger import: -file is required")
	}
	f, err := os.Open(*file) // #nosec G304 -- operator-supplied snapshot file
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSnapshotFile+1))
	_ = f.Close()
	if err != nil {
		return err
	}
	if len(raw) > maxSnapshotFile {
		return fmt.Errorf("ledger import: the file is over %d bytes", maxSnapshotFile)
	}
	res, err := signer.ImportLedger(dir, raw, *replace, time.Now())
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "imported %s: %d organizations, %d entries, %d exclusions; default mode now %s\n",
		res.SnapshotSHA256, res.Tenants, res.Entries, res.Exclusions, jobsign.LedgerEnforce)
	return nil
}

// ledgerConfig reads SIGNER_LEDGER and SIGNER_LEDGER_MIN_APPROVALS.
func ledgerConfig(cfg *signer.Config) error {
	mode, err := signer.ParseLedgerMode(os.Getenv("SIGNER_LEDGER"))
	if err != nil {
		return err
	}
	cfg.LedgerMode = mode
	if v := os.Getenv("SIGNER_LEDGER_MIN_APPROVALS"); v != "" {
		switch v {
		case "0", "1", "2":
			cfg.LedgerMinApprovals = int(v[0] - '0')
		default:
			return errors.New("SIGNER_LEDGER_MIN_APPROVALS must be 0, 1 or 2")
		}
	}
	return nil
}
