package jobs

import (
	"context"
	"fmt"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// WorkerConfig holds the configuration for the job worker.
type WorkerConfig struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Concurrency   int
}

// WorkerOption is a functional option for configuring the Worker.
type WorkerOption func(*Worker)

// Worker processes background jobs.
type Worker struct {
	server                *asynq.Server
	mux                   *asynq.ServeMux
	logger                *logger.Logger
	notificationProcessor NotificationProcessor
	aiTriageProcessor     AITriageProcessor
}

// WithNotificationProcessor adds a notification processor to the worker.
func WithNotificationProcessor(processor NotificationProcessor) WorkerOption {
	return func(w *Worker) {
		w.notificationProcessor = processor
	}
}

// WithAITriageProcessor adds an AI triage processor to the worker.
func WithAITriageProcessor(processor AITriageProcessor) WorkerOption {
	return func(w *Worker) {
		w.aiTriageProcessor = processor
	}
}

// NewWorker creates a new background job worker.
func NewWorker(cfg WorkerConfig, emailService *app.EmailService, log *logger.Logger, opts ...WorkerOption) (*Worker, error) {
	server := asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		},
		asynq.Config{
			Concurrency: cfg.Concurrency,
			Queues: map[string]int{
				"default":       10,
				"email":         5,
				"notifications": 5,
				"ai_triage":     3,
				"maintenance":   2,
			},
		},
	)

	mux := asynq.NewServeMux()

	// Register email handlers
	emailHandler := NewEmailTaskHandler(emailService, log)
	mux.HandleFunc(TypeEmailTeamInvitation, emailHandler.HandleTeamInvitation)
	mux.HandleFunc(TypeEmailWelcome, emailHandler.HandleWelcomeEmail)
	mux.HandleFunc(TypeEmailVerification, emailHandler.HandleVerificationEmail)
	mux.HandleFunc(TypeEmailPasswordReset, emailHandler.HandlePasswordReset)

	w := &Worker{
		server: server,
		mux:    mux,
		logger: log,
	}

	// Apply options
	for _, opt := range opts {
		opt(w)
	}

	// Register notification handlers if processor is provided
	if w.notificationProcessor != nil {
		notificationHandler := NewNotificationTaskHandler(w.notificationProcessor, log.Logger)
		notificationHandler.RegisterHandlers(mux)
		log.Info("notification task handlers registered")
	}

	// Register AI triage handlers if processor is provided
	if w.aiTriageProcessor != nil {
		aiTriageHandler := NewAITriageTaskHandler(w.aiTriageProcessor, log.Logger)
		aiTriageHandler.RegisterHandlers(mux)
		log.Info("AI triage task handlers registered")
	}

	return w, nil
}

// Start starts the worker.
func (w *Worker) Start() error {
	w.logger.Info("starting job worker")
	return w.server.Start(w.mux)
}

// Stop stops the worker gracefully.
func (w *Worker) Stop() {
	w.logger.Info("stopping job worker")
	w.server.Shutdown()
}

// Shutdown is an alias for Stop for compatibility.
func (w *Worker) Shutdown() {
	w.Stop()
}

// Run runs the worker until shutdown.
func (w *Worker) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- w.server.Start(w.mux)
	}()

	select {
	case <-ctx.Done():
		w.Stop()
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("worker error: %w", err)
		}
		return nil
	}
}
