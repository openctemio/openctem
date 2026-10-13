package toolbudget

import "time"

// Task budget bounds (research/122): every budget a command carries is
// clamped, so neither a learned value nor a large chunk can make one
// unbounded or meaninglessly small.
const (
	MinTask  = 5 * time.Minute
	MaxTask  = 24 * time.Hour
	MinStall = 5 * time.Minute
	MaxStall = time.Hour
)

// Task is the budget one command carries in its payload ("budget"): the
// per-target budget the sensor enforces per target, the expected time of
// the whole task (the sensor stops it at twice this), and how long it may go
// without finishing a target before the platform calls it stalled.
type Task struct {
	TargetSeconds int `json:"target_seconds"`
	TaskSeconds   int `json:"task_seconds"`
	StallSeconds  int `json:"stall_seconds"`
}

// PerTarget is the per-target budget: three times the expected time per
// target, within [Floor, Ceiling].
func (b Budget) PerTarget() time.Duration {
	return clamp(3*b.Expected, b.Floor, b.Ceiling)
}

// ForTask returns the budget of a task of the tool over n targets:
// overhead plus ceil(n / concurrency) rounds of the per-target budget,
// within [MinTask, MaxTask]; the stall window is three per-target budgets,
// within [MinStall, MaxStall].
func ForTask(tool string, n int) Task {
	b := For(tool)
	per := b.PerTarget()
	rounds := max((n+b.Concurrency-1)/b.Concurrency, 1)
	task := clamp(b.Overhead+time.Duration(rounds)*per, MinTask, MaxTask)
	stall := clamp(3*per, MinStall, MaxStall)
	return Task{
		TargetSeconds: int(per / time.Second),
		TaskSeconds:   int(task / time.Second),
		StallSeconds:  int(stall / time.Second),
	}
}

func clamp(d, lo, hi time.Duration) time.Duration { return max(lo, min(hi, d)) }
