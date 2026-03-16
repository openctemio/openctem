package middleware

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/openctemio/api/middleware"

// Tracing returns an OpenTelemetry tracing middleware that creates spans
// for each HTTP request and propagates trace context.
func Tracing(serviceName string) func(http.Handler) http.Handler {
	tracer := otel.Tracer(tracerName)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract trace context from incoming request headers
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Create span with normalized path to avoid cardinality explosion
			normalizedPath := normalizePath(r.URL.Path)
			spanName := fmt.Sprintf("%s %s", r.Method, normalizedPath)

			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.request.method", r.Method),
					attribute.String("url.path", r.URL.Path),
					attribute.String("url.scheme", r.URL.Scheme),
					attribute.String("server.address", r.Host),
					attribute.String("http.route", normalizedPath),
				),
			)
			defer span.End()

			// Add request ID to span if available
			if requestID := GetRequestID(r.Context()); requestID != "" {
				span.SetAttributes(attribute.String("request.id", requestID))
			}

			// Inject trace context into response headers for downstream correlation
			otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(w.Header()))

			// Wrap response writer to capture status code
			tw := &tracingResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(tw, r.WithContext(ctx))

			// Record response attributes
			span.SetAttributes(
				attribute.Int("http.response.status_code", tw.statusCode),
			)

			if tw.statusCode >= 400 {
				span.SetAttributes(attribute.Bool("error", true))
			}
		})
	}
}

type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (tw *tracingResponseWriter) WriteHeader(code int) {
	tw.statusCode = code
	tw.ResponseWriter.WriteHeader(code)
}
