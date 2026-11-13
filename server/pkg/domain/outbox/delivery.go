package outbox

import (
	"strings"
	"time"
)

// Per-channel delivery state of one outbox entry. Every channel (integration)
// an event goes to has its own attempts, backoff and outcome, so one channel's
// success never ends the retries of another, and a channel that already got
// the event is never sent it again. Design: docs/architecture/notification-system.md
// ("Delivery per channel").

// DeliveryStatus is the state of one channel's delivery.
type DeliveryStatus string

const (
	// DeliveryPending: not delivered yet; retried at NextAttemptAt.
	DeliveryPending DeliveryStatus = "pending"
	// DeliverySucceeded: the channel accepted the event.
	DeliverySucceeded DeliveryStatus = "success"
	// DeliveryDead: retries exhausted, or the channel may no longer receive
	// the event. Terminal; a redelivery is a new outbox entry.
	DeliveryDead DeliveryStatus = "dead"
)

// DeliveryBackoff is the wait before each retry of a failed channel: the
// first retry 1 minute after the first failure, the last one 24 hours after
// the previous. A channel gets 1 + len(DeliveryBackoff) attempts in all
// (about 45 hours), then it is dead.
var DeliveryBackoff = []time.Duration{
	time.Minute,
	5 * time.Minute,
	30 * time.Minute,
	2 * time.Hour,
	6 * time.Hour,
	12 * time.Hour,
	24 * time.Hour,
}

// MaxDeliveryAttempts is the number of attempts a channel gets.
func MaxDeliveryAttempts() int { return len(DeliveryBackoff) + 1 }

// maxDeliveryErrorLen bounds the stored error of one attempt. Notifier errors
// are already redacted and bounded; this keeps the row small.
const maxDeliveryErrorLen = 500

// ChannelDelivery is one channel's delivery of an outbox entry.
type ChannelDelivery struct {
	IntegrationID   string         `json:"integration_id"`
	IntegrationName string         `json:"name,omitempty"`
	Provider        string         `json:"provider,omitempty"`
	Status          DeliveryStatus `json:"status"`
	Attempts        int            `json:"attempts"`
	NextAttemptAt   *time.Time     `json:"next_attempt_at,omitempty"`
	LastAttemptAt   *time.Time     `json:"last_attempt_at,omitempty"`
	LastError       string         `json:"last_error,omitempty"`
	MessageID       string         `json:"message_id,omitempty"`
}

// NewChannelDelivery is a pending delivery due now.
func NewChannelDelivery(integrationID, name, provider string) ChannelDelivery {
	return ChannelDelivery{
		IntegrationID:   integrationID,
		IntegrationName: name,
		Provider:        provider,
		Status:          DeliveryPending,
	}
}

// Due reports whether the channel should be attempted at now.
func (d ChannelDelivery) Due(now time.Time) bool {
	return d.Status == DeliveryPending && (d.NextAttemptAt == nil || !d.NextAttemptAt.After(now))
}

// RecordSuccess marks the channel delivered.
func (d *ChannelDelivery) RecordSuccess(now time.Time, messageID string) {
	d.Attempts++
	d.Status = DeliverySucceeded
	d.LastAttemptAt = &now
	d.NextAttemptAt = nil
	d.LastError = ""
	d.MessageID = messageID
}

// RecordFailure counts a failed attempt and schedules the next one from
// DeliveryBackoff, or marks the channel dead once its attempts are spent.
func (d *ChannelDelivery) RecordFailure(now time.Time, errMsg string) {
	d.Attempts++
	d.LastAttemptAt = &now
	d.LastError = truncateError(errMsg)
	if d.Attempts >= MaxDeliveryAttempts() {
		d.Status = DeliveryDead
		d.NextAttemptAt = nil
		return
	}
	next := now.Add(DeliveryBackoff[d.Attempts-1])
	d.Status = DeliveryPending
	d.NextAttemptAt = &next
}

// Abandon ends the channel's delivery without another attempt (the channel
// may no longer receive the event). It does not count as an attempt.
func (d *ChannelDelivery) Abandon(now time.Time, reason string) {
	d.Status = DeliveryDead
	d.LastAttemptAt = &now
	d.NextAttemptAt = nil
	d.LastError = truncateError(reason)
}

func truncateError(s string) string {
	if len(s) <= maxDeliveryErrorLen {
		return s
	}
	return s[:maxDeliveryErrorLen]
}

// Deliveries returns the per-channel delivery state (empty before the first
// processing pass resolved the channels).
func (o *Outbox) Deliveries() []ChannelDelivery { return o.deliveries }

// HasDeliveries reports whether the entry's channels are resolved.
func (o *Outbox) HasDeliveries() bool { return len(o.deliveries) > 0 }

// SetDeliveries replaces the per-channel delivery state (restore from
// storage, first resolution of the channels, or a redelivery to one channel).
func (o *Outbox) SetDeliveries(ds []ChannelDelivery) { o.deliveries = ds }

// SettleDeliveries derives the entry's state from its channels after a
// processing pass. While a channel is pending the entry goes back to pending,
// scheduled at the earliest channel retry, and the call returns false. When
// every channel is delivered or dead the entry is completed and the call
// returns true; the caller archives it.
func (o *Outbox) SettleDeliveries(now time.Time) (settled bool) {
	var next *time.Time
	maxAttempts := 0
	var errs []string
	for i := range o.deliveries {
		d := o.deliveries[i]
		if d.Attempts > maxAttempts {
			maxAttempts = d.Attempts
		}
		if d.Status != DeliveryPending {
			if d.Status == DeliveryDead && d.LastError != "" {
				errs = append(errs, d.IntegrationName+": "+d.LastError)
			}
			continue
		}
		if d.LastError != "" {
			errs = append(errs, d.IntegrationName+": "+d.LastError)
		}
		at := now
		if d.NextAttemptAt != nil {
			at = *d.NextAttemptAt
		}
		if next == nil || at.Before(*next) {
			next = &at
		}
	}
	o.lastError = truncateError(strings.Join(errs, "; "))
	// retry_count reports the re-attempts of the busiest channel; the column
	// check (retry_count <= max_retries + 1) holds because max_retries is the
	// channel retry budget.
	o.maxRetries = len(DeliveryBackoff)
	if maxAttempts > 0 {
		o.retryCount = maxAttempts - 1
	}
	o.updatedAt = now
	o.lockedAt = nil
	o.lockedBy = ""
	if next != nil {
		o.status = OutboxStatusPending
		o.scheduledAt = *next
		return false
	}
	o.status = OutboxStatusCompleted
	o.processedAt = &now
	return true
}

// DeliveryResults summarizes the channels for the archive.
func (o *Outbox) DeliveryResults() (succeeded, failed int, results []SendResult) {
	results = make([]SendResult, 0, len(o.deliveries))
	for _, d := range o.deliveries {
		r := SendResult{
			IntegrationID:   d.IntegrationID,
			IntegrationName: d.IntegrationName,
			Provider:        d.Provider,
			MessageID:       d.MessageID,
			Error:           d.LastError,
			Attempts:        d.Attempts,
		}
		if d.LastAttemptAt != nil {
			r.SentAt = *d.LastAttemptAt
		}
		if d.Status == DeliverySucceeded {
			r.Status = "success"
			r.Error = ""
			succeeded++
		} else {
			r.Status = "failed"
			failed++
		}
		results = append(results, r)
	}
	return succeeded, failed, results
}
