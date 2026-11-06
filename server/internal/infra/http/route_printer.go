package http

import (
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strings"
)

// RouteInfo holds information about a registered route.
type RouteInfo struct {
	Method      string
	Path        string
	Handler     string
	Middlewares []string
}

// RouteStats holds route statistics.
type RouteStats struct {
	Total   int
	Methods map[string]int
	Routes  []RouteInfo
}

// CollectRoutes walks the router and collects all registered routes.
func CollectRoutes(router Router) RouteStats {
	stats := RouteStats{
		Methods: make(map[string]int),
		Routes:  []RouteInfo{},
	}

	_ = router.Walk(func(method, path string, handler http.Handler) error {
		handlerName := getHandlerName(handler)

		stats.Routes = append(stats.Routes, RouteInfo{
			Method:  method,
			Path:    path,
			Handler: handlerName,
		})
		stats.Methods[method]++
		stats.Total++
		return nil
	})

	return stats
}

// getHandlerName extracts the handler function name using reflection.
func getHandlerName(handler http.Handler) string {
	// Try to get the function name
	handlerFunc := runtime.FuncForPC(reflect.ValueOf(handler).Pointer())
	if handlerFunc != nil {
		fullName := handlerFunc.Name()
		// Extract just the function name (last part after /)
		parts := strings.Split(fullName, "/")
		if len(parts) > 0 {
			name := parts[len(parts)-1]
			// Clean up common suffixes
			name = strings.TrimSuffix(name, "-fm")
			return name
		}
		return fullName
	}
	return fmt.Sprintf("%T", handler)
}

// PrintRoutes prints routes to the given writer in the specified format.
func PrintRoutes(w io.Writer, stats RouteStats, format string, filters RouteFilters) {
	// Apply filters
	filtered := filterRoutes(stats.Routes, filters)

	// Sort routes
	sortRoutes(filtered, filters.SortBy)

	switch format {
	case "json":
		printJSON(w, filtered, stats)
	case "csv":
		printCSV(w, filtered)
	case "simple":
		printSimple(w, filtered)
	default:
		printTable(w, filtered, stats)
	}
}

// RouteFilters contains filter options for route listing.
type RouteFilters struct {
	Method string
	Path   string
	SortBy string
}

func filterRoutes(routes []RouteInfo, filters RouteFilters) []RouteInfo {
	if filters.Method == "" && filters.Path == "" {
		return routes
	}

	filtered := make([]RouteInfo, 0, len(routes))
	for _, r := range routes {
		if filters.Method != "" && !strings.EqualFold(r.Method, filters.Method) {
			continue
		}
		if filters.Path != "" && !strings.Contains(r.Path, filters.Path) {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

func sortRoutes(routes []RouteInfo, by string) {
	switch by {
	case "method":
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Method == routes[j].Method {
				return routes[i].Path < routes[j].Path
			}
			return routes[i].Method < routes[j].Method
		})
	case "handler":
		sort.Slice(routes, func(i, j int) bool {
			return routes[i].Handler < routes[j].Handler
		})
	default: // path
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Path == routes[j].Path {
				return routes[i].Method < routes[j].Method
			}
			return routes[i].Path < routes[j].Path
		})
	}
}

func printTable(w io.Writer, routes []RouteInfo, stats RouteStats) {
	fmt.Fprintln(w, "API Routes")
	fmt.Fprintln(w, "==========")
	fmt.Fprintf(w, "Total: %d routes\n\n", stats.Total)

	fmt.Fprintln(w, "By Method:")
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for _, m := range methods {
		if count, ok := stats.Methods[m]; ok {
			fmt.Fprintf(w, "  %-8s %d\n", m, count)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("-", 120))
	fmt.Fprintf(w, "%-8s %-50s %s\n", "METHOD", "PATH", "HANDLER")
	fmt.Fprintln(w, strings.Repeat("-", 120))

	for _, r := range routes {
		// Truncate handler name if too long
		handler := r.Handler
		if len(handler) > 55 {
			handler = "..." + handler[len(handler)-52:]
		}
		fmt.Fprintf(w, "%-8s %-50s %s\n", r.Method, r.Path, handler)
	}

	fmt.Fprintln(w, strings.Repeat("-", 120))
	fmt.Fprintf(w, "Showing %d routes\n", len(routes))
}

func printJSON(w io.Writer, routes []RouteInfo, stats RouteStats) {
	fmt.Fprintln(w, "{")
	fmt.Fprintf(w, "  \"total\": %d,\n", stats.Total)
	fmt.Fprintln(w, "  \"methods\": {")
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for i, m := range methods {
		count := stats.Methods[m]
		comma := ","
		if i == len(methods)-1 {
			comma = ""
		}
		fmt.Fprintf(w, "    \"%s\": %d%s\n", m, count, comma)
	}
	fmt.Fprintln(w, "  },")
	fmt.Fprintln(w, "  \"routes\": [")
	for i, r := range routes {
		comma := ","
		if i == len(routes)-1 {
			comma = ""
		}
		fmt.Fprintf(w, "    {\"method\": \"%s\", \"path\": \"%s\", \"handler\": \"%s\"}%s\n",
			r.Method, r.Path, escapeJSON(r.Handler), comma)
	}
	fmt.Fprintln(w, "  ]")
	fmt.Fprintln(w, "}")
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func printCSV(w io.Writer, routes []RouteInfo) {
	fmt.Fprintln(w, "method,path,handler")
	for _, r := range routes {
		// Escape CSV fields
		handler := strings.ReplaceAll(r.Handler, "\"", "\"\"")
		if strings.Contains(handler, ",") {
			handler = "\"" + handler + "\""
		}
		fmt.Fprintf(w, "%s,%s,%s\n", r.Method, r.Path, handler)
	}
}

func printSimple(w io.Writer, routes []RouteInfo) {
	for _, r := range routes {
		fmt.Fprintf(w, "%-8s %s\n", r.Method, r.Path)
	}
}
