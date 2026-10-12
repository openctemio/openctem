package integration

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// exposureGroupedCounter counts a filter's events by state and by severity in
// one query (the postgres repository implements it), for the credential
// stats card that used to send one COUNT per state and per severity.
type exposureGroupedCounter interface {
	CountByStateAndSeverity(ctx context.Context, filter exposure.Filter) (map[string]int64, map[string]int64, error)
}
