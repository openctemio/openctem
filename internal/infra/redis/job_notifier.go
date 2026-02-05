package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/openctemio/api/pkg/logger"
)

const (
	// JobNotifyChannel is the Redis pub/sub channel for job notifications.
	JobNotifyChannel = "platform:jobs:notify"

	// JobNotifyChannelPrefix is the prefix for capability-specific channels.
	JobNotifyChannelPrefix = "platform:jobs:notify:"
)

// JobNotification represents a notification about a new platform job.
type JobNotification struct {
	JobID        string   `json:"job_id"`
	TenantID     string   `json:"tenant_id"`
	Capabilities []string `json:"capabilities,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	Priority     int      `json:"priority"`
	CreatedAt    int64    `json:"created_at"` // Unix timestamp
}

// JobNotifier handles pub/sub notifications for platform jobs.
// It uses Redis pub/sub to notify waiting agents when new jobs are available.
type JobNotifier struct {
	client *Client
	logger *logger.Logger

	// Subscribers waiting for jobs
	mu          sync.RWMutex
	subscribers map[string]chan *JobNotification // agentID -> channel
}

// NewJobNotifier creates a new JobNotifier.
func NewJobNotifier(client *Client, log *logger.Logger) *JobNotifier {
	return &JobNotifier{
		client:      client,
		logger:      log,
		subscribers: make(map[string]chan *JobNotification),
	}
}

// NotifyNewJob publishes a notification that a new job is available.
// This should be called when a new platform job is created.
func (n *JobNotifier) NotifyNewJob(ctx context.Context, notification *JobNotification) error {
	data, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("marshal notification: %w", err)
	}

	// Publish to main channel
	if err := n.client.Client().Publish(ctx, JobNotifyChannel, data).Err(); err != nil {
		return fmt.Errorf("publish to main channel: %w", err)
	}

	// Also publish to capability-specific channels for more targeted delivery
	for _, cap := range notification.Capabilities {
		channel := JobNotifyChannelPrefix + cap
		if err := n.client.Client().Publish(ctx, channel, data).Err(); err != nil {
			n.logger.Warn("failed to publish to capability channel",
				"channel", channel,
				"error", err,
			)
		}
	}

	n.logger.Debug("published job notification",
		"job_id", notification.JobID,
		"capabilities", notification.Capabilities,
	)

	return nil
}

// Subscribe creates a subscription for an agent to receive job notifications.
// Returns a channel that will receive notifications when jobs are available.
// The caller should call Unsubscribe when done.
func (n *JobNotifier) Subscribe(agentID string, capabilities []string) <-chan *JobNotification {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Create buffered channel to avoid blocking publisher
	ch := make(chan *JobNotification, 10)
	n.subscribers[agentID] = ch

	n.logger.Debug("agent subscribed for job notifications",
		"agent_id", agentID,
		"capabilities", capabilities,
	)

	return ch
}

// Unsubscribe removes an agent's subscription.
func (n *JobNotifier) Unsubscribe(agentID string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if ch, ok := n.subscribers[agentID]; ok {
		close(ch)
		delete(n.subscribers, agentID)
		n.logger.Debug("agent unsubscribed from job notifications",
			"agent_id", agentID,
		)
	}
}

// StartListener starts listening for Redis pub/sub messages and
// dispatches them to subscribed agents. This should be called once
// when the application starts.
func (n *JobNotifier) StartListener(ctx context.Context) error {
	pubsub := n.client.Client().Subscribe(ctx, JobNotifyChannel)

	// Wait for subscription confirmation
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return fmt.Errorf("subscribe to channel: %w", err)
	}

	n.logger.Info("job notifier listening for notifications",
		"channel", JobNotifyChannel,
	)

	go n.listenLoop(ctx, pubsub)

	return nil
}

func (n *JobNotifier) listenLoop(ctx context.Context, pubsub *redis.PubSub) {
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			n.logger.Info("job notifier stopping")
			return

		case msg, ok := <-ch:
			if !ok {
				n.logger.Warn("pub/sub channel closed")
				return
			}

			var notification JobNotification
			if err := json.Unmarshal([]byte(msg.Payload), &notification); err != nil {
				n.logger.Error("failed to unmarshal notification",
					"payload", msg.Payload,
					"error", err,
				)
				continue
			}

			// Dispatch to all subscribers
			n.dispatchNotification(&notification)
		}
	}
}

func (n *JobNotifier) dispatchNotification(notification *JobNotification) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	dispatched := 0
	for agentID, ch := range n.subscribers {
		select {
		case ch <- notification:
			dispatched++
		default:
			// Channel full, agent is busy
			n.logger.Debug("agent channel full, skipping notification",
				"agent_id", agentID,
				"job_id", notification.JobID,
			)
		}
	}

	n.logger.Debug("dispatched job notification",
		"job_id", notification.JobID,
		"subscribers", len(n.subscribers),
		"dispatched", dispatched,
	)
}

// WaitForJob waits for a job notification or timeout.
// This is the main method used by the long-polling handler.
// Returns true if a notification was received, false on timeout.
func (n *JobNotifier) WaitForJob(ctx context.Context, agentID string, capabilities []string, timeout time.Duration) bool {
	ch := n.Subscribe(agentID, capabilities)
	defer n.Unsubscribe(agentID)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	case _, ok := <-ch:
		return ok
	}
}

// SubscriberCount returns the current number of subscribers.
func (n *JobNotifier) SubscriberCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.subscribers)
}

// =============================================================================
// App Layer Interface Adapters
// =============================================================================

// NotifyNewPlatformJob is an adapter method that accepts app.PlatformJobNotification
// and converts it to the internal JobNotification format.
// This allows JobNotifier to implement app.PlatformJobNotifier interface.
func (n *JobNotifier) NotifyNewPlatformJob(ctx context.Context, jobID, tenantID string, capabilities, tools []string, priority int, createdAt int64) error {
	notification := &JobNotification{
		JobID:        jobID,
		TenantID:     tenantID,
		Capabilities: capabilities,
		Tools:        tools,
		Priority:     priority,
		CreatedAt:    createdAt,
	}
	return n.NotifyNewJob(ctx, notification)
}
