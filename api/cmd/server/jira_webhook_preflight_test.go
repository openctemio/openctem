package main

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// Without a database (bootstrap) the check neither panics nor reports.
func TestJiraWebhookPreflight_NilDB(t *testing.T) {
	n, err := countJiraIntegrationsWithoutSecret(context.Background(), nil)
	if err != nil || n != 0 {
		t.Fatalf("nil DB: got (%d, %v), want (0, nil)", n, err)
	}
	warnJiraIntegrationsWithoutSecret(context.Background(), nil, logger.NewNop())
}
