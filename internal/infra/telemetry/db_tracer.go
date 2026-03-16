package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const dbTracerName = "github.com/openctemio/api/postgres"

// StartDBSpan starts a new span for a database operation.
// Usage:
//
//	ctx, span := telemetry.StartDBSpan(ctx, "FindingRepository.GetByID")
//	defer span.End()
func StartDBSpan(ctx context.Context, operation string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tracer := Tracer(dbTracerName)

	defaultAttrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.operation", operation),
	}
	defaultAttrs = append(defaultAttrs, attrs...)

	return tracer.Start(ctx, "db."+operation,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(defaultAttrs...),
	)
}

// RecordDBError records an error on the current span.
func RecordDBError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("error", true))
	}
}
