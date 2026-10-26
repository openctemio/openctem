/**
 * @name Log entries created from user input (outside structured attributes)
 * @description The standard log-injection query, without the sinks the
 *              structured logger escapes: the key-value attributes of a
 *              log/slog call. slog's text and JSON handlers (the only ones
 *              pkg/logger builds, pinned by pkg/logger/forging_test.go) quote
 *              or escape every attribute value, so CR/LF in an attribute
 *              cannot forge a log line. The message argument of a slog call,
 *              and every other logger (log, fmt, third-party), stay sinks,
 *              with the standard sanitizers (strings.ReplaceAll of CR or LF,
 *              %q), which pkg/logger.SanitizeValue/SanitizeText/SanitizeError
 *              use.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id openctem/go/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import go
import semmle.go.security.LogInjection

/** The position of the message parameter of a log/slog logging call, by name. */
bindingset[name]
int slogMessageIndex(string name) {
  name = ["Debug", "Info", "Warn", "Error"] and result = 0
  or
  name = ["DebugContext", "InfoContext", "WarnContext", "ErrorContext"] and result = 1
  or
  name = ["Log", "LogAttrs"] and result = 2
}

/** A key-value attribute argument of a log/slog call (escaped by the handler). */
predicate slogAttribute(DataFlow::Node n) {
  exists(DataFlow::CallNode c, Function f |
    f = c.getTarget() and
    f.getPackage().getPath() = "log/slog"
  |
    exists(int msg | msg = slogMessageIndex(f.getName()) |
      n.(DataFlow::ImplicitVarargsSlice).getCallNode() = c
      or
      exists(int j | j > msg and n = c.getSyntacticArgument(j))
    )
    or
    f.getName() = ["With", "WithGroup"] and
    (n.(DataFlow::ImplicitVarargsSlice).getCallNode() = c or n = c.getSyntacticArgument(_))
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { LogInjection::Config::isSource(source) }

  predicate isSink(DataFlow::Node sink) {
    LogInjection::Config::isSink(sink) and not slogAttribute(sink)
  }

  predicate isBarrier(DataFlow::Node node) { LogInjection::Config::isBarrier(node) }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
