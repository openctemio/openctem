package controller

import (
	"context"
	"errors"
	"time"

	programfeedapp "github.com/openctemio/openctem/api/internal/app/programfeed"
)

// ProgramFeedImporter imports the public program feed and reconciles the
// subscribed programs (*programfeed.Importer).
type ProgramFeedImporter interface {
	Import(ctx context.Context) (*programfeedapp.Result, error)
	Reconcile(ctx context.Context) map[string]int
}

// ProgramFeedController imports the signed public program feed every hour
// and, on every tick, brings subscribed programs that differ from the
// catalog up to date, so a failed update is retried (RFC-065 §16).
type ProgramFeedController struct {
	name     string
	importer ProgramFeedImporter
}

// NewProgramFeedController creates the controller of one stream.
func NewProgramFeedController(name string, i ProgramFeedImporter) *ProgramFeedController {
	return &ProgramFeedController{name: name, importer: i}
}

// Name implements Controller.
func (c *ProgramFeedController) Name() string { return c.name }

// Interval implements Controller.
func (c *ProgramFeedController) Interval() time.Duration { return time.Hour }

// Reconcile implements Controller: the number of subscribed programs
// updated.
func (c *ProgramFeedController) Reconcile(ctx context.Context) (int, error) {
	if c.importer == nil {
		return 0, nil
	}
	res, err := c.importer.Import(ctx)
	if errors.Is(err, programfeedapp.ErrSourceDisabled) {
		return 0, nil // the administrator has not enabled the local source
	}
	if err != nil {
		// A refused or missing bundle keeps the catalog; subscriptions are
		// still reconciled against it.
		n := count(c.importer.Reconcile(ctx))
		return n, err
	}
	return count(res.Subscribers), nil
}

func count(m map[string]int) int {
	n := 0
	for k, v := range m {
		if k != programfeedapp.OutcomeFailed {
			n += v
		}
	}
	return n
}
