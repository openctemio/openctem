// Package toolbudget holds how long a tool is expected to spend per target:
// the layered budgets of research/122 (target, task, step, run). A budget
// is used to size, admit and display work; the run's deadline stays a policy
// cap, and a slow but alive command is kept going by its lease.
package toolbudget

import (
	"strings"
	"time"
)

// Budget is one tool's time per target. Every duration is a default chosen
// from live per-target durations with headroom; learned values (when there
// are any) are clamped to [Floor, Ceiling] so a slow or hostile target
// cannot stretch a budget without bound.
type Budget struct {
	// Expected is the typical time one target takes.
	Expected time.Duration
	// Floor and Ceiling bound any per-target budget of the tool.
	Floor, Ceiling time.Duration
	// Concurrency is how many targets the tool works on at once.
	Concurrency int
	// Overhead is the fixed cost of one task (start, content load, upload).
	Overhead time.Duration
}

// fallback is the budget of a tool with no entry: conservative, serial.
var fallback = Budget{Expected: 2 * time.Minute, Floor: 10 * time.Second, Ceiling: time.Hour, Concurrency: 1, Overhead: time.Minute}

var defaults = map[string]Budget{
	"subfinder": {Expected: 30 * time.Second, Floor: 10 * time.Second, Ceiling: 10 * time.Minute, Concurrency: 1, Overhead: 30 * time.Second},
	"dnsx":      {Expected: 2 * time.Second, Floor: time.Second, Ceiling: 30 * time.Second, Concurrency: 50, Overhead: 15 * time.Second},
	"naabu":     {Expected: time.Minute, Floor: 10 * time.Second, Ceiling: 15 * time.Minute, Concurrency: 10, Overhead: 30 * time.Second},
	"httpx":     {Expected: 5 * time.Second, Floor: 2 * time.Second, Ceiling: time.Minute, Concurrency: 25, Overhead: 30 * time.Second},
	"katana":    {Expected: 5 * time.Minute, Floor: 30 * time.Second, Ceiling: 30 * time.Minute, Concurrency: 5, Overhead: time.Minute},
	"nuclei":    {Expected: 5 * time.Minute, Floor: time.Minute, Ceiling: time.Hour, Concurrency: 10, Overhead: 2 * time.Minute},
}

// For returns tool's budget (the fallback for a tool with no entry). The
// name is matched case-insensitively.
func For(tool string) Budget {
	if b, ok := defaults[strings.ToLower(strings.TrimSpace(tool))]; ok {
		return b
	}
	return fallback
}

// MinUseful is the least time a task of the tool needs to do anything
// useful: its overhead plus one expected target. A step is not dispatched
// when less than this is left before its run's deadline: it would only be
// started to be canceled.
func (b Budget) MinUseful() time.Duration { return b.Overhead + b.Expected }
