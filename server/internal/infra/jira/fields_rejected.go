package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// FieldRejectedError is a 400 from Jira that names the fields it refused
// ({"errors": {"customfield_10050": "...", "issuetype": "..."}}). Only the
// field ids are kept; Jira's messages are dropped (untrusted text that may
// carry personal data). It unwraps to the upstream status error.
type FieldRejectedError struct {
	Fields []string
	Err    *httpsec.UpstreamStatusError
}

func (e *FieldRejectedError) Error() string {
	return fmt.Sprintf("jira refused fields %v: %v", e.Fields, e.Err)
}

func (e *FieldRejectedError) Unwrap() error { return e.Err }

// maxFieldErrors bounds the field ids read from one refusal.
const maxFieldErrors = 50

// upstreamError builds the error of a non-2xx answer: a field refusal when a
// 400 names fields, the generic upstream status error otherwise.
func upstreamError(ctx context.Context, status int, body []byte) error {
	ue := httpsec.NewUpstreamStatusError(ctx, "jira", status, body)
	if status != http.StatusBadRequest {
		return ue
	}
	var parsed struct {
		Errors map[string]json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Errors) == 0 {
		return ue
	}
	fields := make([]string, 0, len(parsed.Errors))
	for k := range parsed.Errors {
		if len(fields) == maxFieldErrors {
			break
		}
		fields = append(fields, k)
	}
	return &FieldRejectedError{Fields: fields, Err: ue}
}

// GetIssueTypeID reads an issue's current issue type id.
func (c *Client) GetIssueTypeID(ctx context.Context, issueKey string) (string, error) {
	var resp struct {
		Fields struct {
			IssueType struct {
				ID string `json:"id"`
			} `json:"issuetype"`
		} `json:"fields"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(issueKey)+"?fields=issuetype", nil, &resp); err != nil {
		return "", err
	}
	return resp.Fields.IssueType.ID, nil
}
