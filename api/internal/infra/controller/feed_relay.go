package controller

// Feed relay (docs/rfcs/RFC-142-feed-relay.md): the controller that plans
// relay rounds and imports what the relay delivered, and the gate that stops
// a feed fetcher from going out while the platform is in relay mode.

import (
	"context"
	"time"
)

// FeedRelayReconciler drives the relay one step (feedrelay.Service).
type FeedRelayReconciler interface {
	Reconcile(ctx context.Context) (int, error)
}

// FeedRelayController runs the relay planner on one replica at a time.
type FeedRelayController struct{ svc FeedRelayReconciler }

// NewFeedRelayController creates the controller.
func NewFeedRelayController(svc FeedRelayReconciler) *FeedRelayController {
	return &FeedRelayController{svc: svc}
}

// Name implements Controller.
func (c *FeedRelayController) Name() string { return "feed-relay" }

// Interval implements Controller.
func (c *FeedRelayController) Interval() time.Duration { return 30 * time.Second }

// ReconcileTimeout: an import of a relayed snapshot takes longer than a tick.
func (c *FeedRelayController) ReconcileTimeout() time.Duration { return 30 * time.Minute }

// Exclusive implements Exclusive: one replica plans and imports.
func (c *FeedRelayController) Exclusive() bool { return true }

// Reconcile implements Controller.
func (c *FeedRelayController) Reconcile(ctx context.Context) (int, error) {
	return c.svc.Reconcile(ctx)
}

// offlineGate skips a controller's run while off reports true.
type offlineGate struct {
	Controller
	off func(ctx context.Context) bool
}

// SkipWhen wraps a controller that fetches from the internet so that it does
// nothing while off reports true (the platform receives its feeds through
// the relay and makes no outbound feed request). The wrapper keeps the
// controller's name, interval, timeout and exclusivity.
func SkipWhen(c Controller, off func(ctx context.Context) bool) Controller {
	if off == nil {
		return c
	}
	g := &offlineGate{Controller: c, off: off}
	_, ex := c.(Exclusive)
	_, to := c.(ReconcileTimeouter)
	switch {
	case ex && to:
		return &struct {
			*offlineGate
			Exclusive
			ReconcileTimeouter
		}{g, c.(Exclusive), c.(ReconcileTimeouter)}
	case ex:
		return &struct {
			*offlineGate
			Exclusive
		}{g, c.(Exclusive)}
	case to:
		return &struct {
			*offlineGate
			ReconcileTimeouter
		}{g, c.(ReconcileTimeouter)}
	}
	return g
}

// Reconcile implements Controller.
func (g *offlineGate) Reconcile(ctx context.Context) (int, error) {
	if g.off(ctx) {
		return 0, nil
	}
	return g.Controller.Reconcile(ctx)
}
