package widgets

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// Brief sentence kinds, in the order they are picked.
const (
	BriefChange = "change"
	BriefLever  = "lever"
	BriefSLADue = "sla_due"
	BriefKEV    = "kev"
	BriefQuiet  = "quiet"
)

// Change variants.
const (
	VariantDown = "down"
	VariantUp   = "up"
	VariantFlat = "flat"
)

// briefDays is the brief's window: the last seven days, today included.
const briefDays = 7

// BriefChip is one figure of a sentence and the list it counts; Drill is
// empty when no list has exactly that total.
type BriefChip struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
	Drill string `json:"drill,omitempty"`
}

// BriefItem is one sentence: a template (Kind, Variant) and its figures.
type BriefItem struct {
	Kind    string      `json:"kind" enums:"change,lever,sla_due,kev,quiet"`
	Variant string      `json:"variant,omitempty" enums:"down,up,flat"`
	Chips   []BriefChip `json:"chips"`
	// Lever is the lever a "lever" sentence words (the levers widget's first).
	Lever *Lever `json:"lever,omitempty"`
}

// BriefValue is the weekly brief: deterministic sentences built from the
// same reads as the other widgets, no generated text.
type BriefValue struct {
	Since time.Time   `json:"since"`
	Items []BriefItem `json:"items"`
}

// brief builds up to three sentences for a scope.
func (s *Service) brief(ctx context.Context, scope dashboard.ReadScope) (*BriefValue, error) {
	to := dayOf(s.now())
	since := to.AddDate(0, 0, -(briefDays - 1))
	out := &BriefValue{Since: since, Items: []BriefItem{}}

	days, err := s.facts.Days(ctx, scope, dashboard.WidgetFilter{}, "", since, to)
	if err != nil {
		return nil, err
	}
	var opened, fixed int64
	for _, d := range days {
		opened += d.Opened
		fixed += d.Fixed
	}
	if opened > 0 || fixed > 0 {
		variant := VariantFlat
		switch {
		case fixed > opened:
			variant = VariantDown
		case opened > fixed:
			variant = VariantUp
		}
		// Daily flow counts are not a list the findings page can express
		// exactly, so these chips open nothing.
		out.Items = append(out.Items, BriefItem{Kind: BriefChange, Variant: variant,
			Chips: []BriefChip{{Key: "opened", Value: opened}, {Key: "fixed", Value: fixed}}})
	}

	lv, err := s.levers(ctx, scope)
	if err != nil {
		return nil, err
	}
	if len(lv.Levers) > 0 {
		l := lv.Levers[0]
		out.Items = append(out.Items, BriefItem{Kind: BriefLever, Lever: &l,
			Chips: []BriefChip{{Key: l.Kind, Value: l.Count, Drill: l.Drill}}})
	}

	classes := []string{"P0", "P1", "P2"}
	dueF := dashboard.WidgetFilter{SLAState: []string{"warning"}, PriorityClass: classes}
	pastF := dashboard.WidgetFilter{SLAState: []string{"breached"}, PriorityClass: classes}
	due, err := s.openCount(ctx, scope, dueF)
	if err != nil {
		return nil, err
	}
	past, err := s.openCount(ctx, scope, pastF)
	if err != nil {
		return nil, err
	}
	if due > 0 || past > 0 {
		out.Items = append(out.Items, BriefItem{Kind: BriefSLADue, Chips: []BriefChip{
			{Key: "due_soon", Value: due, Drill: drillHref(dueF)},
			{Key: "past_sla", Value: past, Drill: drillHref(pastF)},
		}})
	} else {
		kevF := dashboard.WidgetFilter{KEV: boolp(true)}
		kev, err := s.openCount(ctx, scope, kevF)
		if err != nil {
			return nil, err
		}
		if kev > 0 {
			out.Items = append(out.Items, BriefItem{Kind: BriefKEV, Chips: []BriefChip{{Key: "kev_open", Value: kev, Drill: drillHref(kevF)}}})
		}
	}

	if len(out.Items) == 0 {
		out.Items = append(out.Items, BriefItem{Kind: BriefQuiet, Chips: []BriefChip{}})
	}
	return out, nil
}

// briefMetric fills the brief.weekly widget.
func (s *Service) briefMetric(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	b, err := s.brief(ctx, scope)
	if err != nil {
		return err
	}
	v.Brief = b
	return nil
}
