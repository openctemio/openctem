package signer

// The API's side of the signer's scope ledger (RFC-040 §5.6 points 4 and
// 5): scope changes and narrowing syncs sent by the scope service.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// LedgerTimeout bounds one ledger call (a sync carries a whole
// organization).
const LedgerTimeout = 10 * time.Second

// maxLedgerAnswer bounds a ledger answer (status lists every organization).
const maxLedgerAnswer = 8 << 20

// reasonRE is the shape of a signer reason; anything else is not passed on.
var reasonRE = regexp.MustCompile(`^[a-z][a-z_]{0,47}$`)

// refusalOf is the *jobsign.RefusalError of a 4xx answer, nil otherwise.
func refusalOf(status int, raw []byte) *jobsign.RefusalError {
	if status < 400 || status >= 500 {
		return nil
	}
	var r jobsign.Refusal
	_ = json.Unmarshal(raw, &r)
	rf := &jobsign.RefusalError{Status: status, Reason: r.Reason, Detail: r.Detail}
	if !reasonRE.MatchString(rf.Reason) {
		rf.Reason = "other"
	}
	if len(rf.Detail) > 512 {
		rf.Detail = rf.Detail[:512]
	}
	return rf
}

// ApplyLedger sends one scope change. A refusal is a *jobsign.RefusalError;
// any other error means the signer did not answer.
func (c *Client) ApplyLedger(ctx context.Context, ch jobsign.LedgerChange) (jobsign.LedgerApplyResult, error) {
	var out jobsign.LedgerApplyResult
	err := c.ledgerCall(ctx, http.MethodPost, jobsign.LedgerApplyPath, ch, &out)
	return out, err
}

// SyncLedger sends one organization's scope in effect (the signer only
// narrows from it).
func (c *Client) SyncLedger(ctx context.Context, snap jobsign.LedgerSnapshot) (jobsign.LedgerSyncResult, error) {
	var out jobsign.LedgerSyncResult
	err := c.ledgerCall(ctx, http.MethodPost, jobsign.LedgerSyncPath, snap, &out)
	return out, err
}

// LedgerStatus is the signer's ledger mode and the organizations it holds.
func (c *Client) LedgerStatus(ctx context.Context) (jobsign.LedgerStatus, error) {
	var out jobsign.LedgerStatus
	err := c.ledgerCall(ctx, http.MethodGet, jobsign.LedgerPath, nil, &out)
	return out, err
}

func (c *Client) ledgerCall(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, LedgerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("job signer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLedgerAnswer+1))
	if err != nil {
		return fmt.Errorf("job signer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if rf := refusalOf(resp.StatusCode, raw); rf != nil {
			return rf
		}
		return fmt.Errorf("job signer: status %d", resp.StatusCode)
	}
	if len(raw) > maxLedgerAnswer {
		return fmt.Errorf("job signer: answer too large")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("job signer: %w", err)
	}
	return nil
}
