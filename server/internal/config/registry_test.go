package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEnvRegistryParses(t *testing.T) {
	r, err := parseEnvRegistry(envRegistryYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Vars) < 100 || len(r.Prefixes) == 0 {
		t.Fatalf("registry looks empty: %d vars, %d prefixes", len(r.Vars), len(r.Prefixes))
	}
	for _, x := range retiredEnv {
		if _, ok := r.Lookup(x.Old); ok {
			t.Errorf("%s is retired but still registered", x.Old)
		}
	}
	for _, x := range removedEnv {
		if _, ok := r.Lookup(x.Name); ok {
			t.Errorf("%s is removed but still registered", x.Name)
		}
	}
}

// envReaders are the functions whose string-literal arguments name environment
// variables.
var envReaders = map[string]bool{
	"getEnv": true, "getEnvInt": true, "getEnvInt64": true, "getEnvBool": true,
	"getEnvDuration": true, "getEnvFloat": true, "getEnvSlice": true,
	"Getenv": true, "LookupEnv": true, "lookup": true, "feedURLs": true,
	"envFloat": true, "envInt": true,
}

var envLiteralRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*_[A-Z0-9_]+$`)

type envRead struct {
	file string
	def  ast.Expr // second argument of a getEnv* call, or nil
	fn   string
}

// codeEnvReads walks the api module's non-test Go code and returns every
// environment variable name read, keyed by name.
func codeEnvReads(t *testing.T) map[string][]envRead {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	reads := map[string][]envRead{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch rel {
			case "internal/testdb", "tests", "tools", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(rel, "testdata") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if !envReaders[name] {
					return true
				}
				for i, a := range n.Args {
					lit, ok := a.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, _ := strconv.Unquote(lit.Value)
					if !envLiteralRE.MatchString(s) {
						continue
					}
					r := envRead{file: rel, fn: name}
					if i == 0 && len(n.Args) == 2 && strings.HasPrefix(name, "getEnv") {
						r.def = n.Args[1]
					}
					reads[s] = append(reads[s], r)
				}
			case *ast.ValueSpec:
				// const EnvAllowPrivate = "OPENCTEM_HTTPSEC_ALLOW_PRIVATE"
				for i, id := range n.Names {
					if !strings.HasPrefix(id.Name, "Env") || i >= len(n.Values) {
						continue
					}
					if lit, ok := n.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, _ := strconv.Unquote(lit.Value); envLiteralRE.MatchString(s) {
							reads[s] = append(reads[s], envRead{file: rel, fn: "const"})
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return reads
}

// The registry and the code agree: every name the api code reads is
// registered, every registered api/tool name is read, and a literal default
// in the code equals the documented one.
func TestEnvRegistryMatchesCode(t *testing.T) {
	r := Registry()
	reads := codeEnvReads(t)
	var notRegistered []string
	for name := range reads {
		if _, ok := r.Lookup(name); !ok && !retiredOrRemoved(name) {
			notRegistered = append(notRegistered, name+" ("+reads[name][0].file+")")
		}
	}
	slices.Sort(notRegistered)
	for _, n := range notRegistered {
		t.Errorf("read by the code but not in env_registry.yaml: %s", n)
	}
	for i := range r.Vars {
		v := &r.Vars[i]
		if v.Component != "api" && v.Component != "tool" {
			continue
		}
		rs, ok := reads[v.Name]
		if !ok {
			t.Errorf("%s is registered as %s but nothing reads it: remove it (and refuse it in removedEnv)", v.Name, v.Component)
			continue
		}
		for _, rd := range rs {
			if rd.def == nil {
				continue
			}
			if msg := compareDefault(v, rd.fn, rd.def); msg != "" {
				t.Errorf("%s (%s): %s", v.Name, rd.file, msg)
			}
		}
	}
}

// compareDefault checks a literal code default against the registry's.
// Defaults that are not literals (constants, derived values) are skipped.
func compareDefault(v *EnvVar, fn string, def ast.Expr) string {
	code, ok := evalDefault(def)
	if !ok {
		return ""
	}
	documented := strings.TrimSpace(v.Default)
	if documented == "" && isZero(code) {
		return "" // unset means derived; the description says from what
	}
	switch fn {
	case "getEnvDuration":
		want, err := time.ParseDuration(documented)
		if i, isInt := code.(int64); isInt {
			code = time.Duration(i) // an untyped constant: nanoseconds
		}
		got, ok := code.(time.Duration)
		if err != nil || !ok || want != got {
			return "code default " + toString(code) + " differs from documented " + strconv.Quote(documented)
		}
	case "getEnvInt", "getEnvInt64":
		want, err := strconv.ParseInt(strings.Fields(documented + " x")[0], 10, 64)
		got, ok := code.(int64)
		if err != nil || !ok || want != got {
			return "code default " + toString(code) + " differs from documented " + strconv.Quote(documented)
		}
	case "getEnvFloat":
		want, err := strconv.ParseFloat(documented, 64)
		got, ok := code.(float64)
		if !ok {
			if i, isInt := code.(int64); isInt {
				got, ok = float64(i), true
			}
		}
		if err != nil || !ok || want != got {
			return "code default " + toString(code) + " differs from documented " + strconv.Quote(documented)
		}
	case "getEnvBool":
		want, err := strconv.ParseBool(documented)
		got, ok := code.(bool)
		if err != nil || !ok || want != got {
			return "code default " + toString(code) + " differs from documented " + strconv.Quote(documented)
		}
	case "getEnv":
		got, ok := code.(string)
		if ok && got != documented {
			return "code default " + strconv.Quote(got) + " differs from documented " + strconv.Quote(documented)
		}
	}
	return ""
}

func isZero(v any) bool {
	switch x := v.(type) {
	case time.Duration:
		return x == 0
	case int64:
		return x == 0
	case float64:
		return x == 0
	case bool:
		return !x
	case string:
		return x == ""
	}
	return false
}

func toString(v any) string {
	switch x := v.(type) {
	case time.Duration:
		return x.String()
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case string:
		return strconv.Quote(x)
	}
	return "?"
}

var timeUnits = map[string]time.Duration{
	"Nanosecond": time.Nanosecond, "Microsecond": time.Microsecond, "Millisecond": time.Millisecond,
	"Second": time.Second, "Minute": time.Minute, "Hour": time.Hour,
}

// evalDefault evaluates the literal forms defaults take: "x", 42, 0.5, true,
// time.Hour, 15*time.Second, 10<<20.
func evalDefault(e ast.Expr) (any, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING:
			s, err := strconv.Unquote(x.Value)
			return s, err == nil
		case token.INT:
			i, err := strconv.ParseInt(x.Value, 0, 64)
			return i, err == nil
		case token.FLOAT:
			f, err := strconv.ParseFloat(x.Value, 64)
			return f, err == nil
		}
	case *ast.Ident:
		switch x.Name {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "time" {
			d, ok := timeUnits[x.Sel.Name]
			return d, ok
		}
	case *ast.BinaryExpr:
		l, lok := evalDefault(x.X)
		r, rok := evalDefault(x.Y)
		if !lok || !rok {
			return nil, false
		}
		li, lInt := l.(int64)
		switch x.Op {
		case token.MUL:
			if rd, ok := r.(time.Duration); ok && lInt {
				return time.Duration(li) * rd, true
			}
			if ri, ok := r.(int64); ok && lInt {
				return li * ri, true
			}
		case token.SHL:
			if ri, ok := r.(int64); ok && lInt {
				return li << ri, true
			}
		}
	}
	return nil, false
}

func TestCheckEnvironment(t *testing.T) {
	r := Registry()
	cases := []struct {
		name     string
		env      []string
		wantErr  []string
		wantWarn []string
	}{
		{"clean", []string{"REDIS_PASSWORD=x", "PATH=/bin", "HOME=/root"}, nil, nil},
		{"typo is refused with a suggestion", []string{"REDIS_PASWORD=hunter2"}, []string{"REDIS_PASWORD (did you mean REDIS_PASSWORD?)"}, nil},
		{"unrelated name under a prefix only warns", []string{"AI_AGENT=claude"}, nil, []string{"AI_AGENT is set but not read by the API"}},
		{"kubernetes service links are ignored", []string{"REDIS_SERVICE_HOST=10.0.0.1", "REDIS_PORT_6379_TCP_ADDR=10.0.0.1", "REDIS_PORT=tcp://10.0.0.1:6379"}, nil, nil},
		{"bad int", []string{"SERVER_PORT=eighty"}, []string{"SERVER_PORT is not an integer"}, nil},
		{"bad bool", []string{"RATE_LIMIT_ENABLED=yes"}, []string{"RATE_LIMIT_ENABLED is not true or false"}, nil},
		{"bad duration", []string{"AUTH_ACCESS_TOKEN_DURATION=1d"}, []string{"AUTH_ACCESS_TOKEN_DURATION is not a duration"}, nil},
		{"bad enum", []string{"SENSOR_TRANSPORT_V3=on"}, []string{"SENSOR_TRANSPORT_V3 must be one of auto, off"}, nil},
		{"empty value is unset", []string{"SERVER_PORT="}, nil, nil},
		{"retired names are left to rejectRetiredEnv", []string{"AGENT_KEY_TTL=1h"}, nil, nil},
		{"other components' names are known", []string{"OPENCTEM_TLS_MODE=internal", "SENSOR_MTLS_UPSTREAM=api:9443", "DB_MIGRATE_USER=owner"}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := checkEnvironment(r, tc.env)
			if len(tc.wantErr) == 0 && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, w := range tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Errorf("error %v does not contain %q", err, w)
				}
			}
			if !slices.Equal(warn, tc.wantWarn) {
				t.Errorf("warnings = %v, want %v", warn, tc.wantWarn)
			}
		})
	}
}

// A refusal names the variable, never its value: values may be secrets.
func TestCheckEnvironment_NeverPrintsValues(t *testing.T) {
	_, err := checkEnvironment(Registry(), []string{"REDIS_PASWORD=hunter2-secret", "SERVER_PORT=s3cr3t-value"})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, v := range []string{"hunter2-secret", "s3cr3t-value"} {
		if strings.Contains(err.Error(), v) {
			t.Errorf("error leaks a value: %v", err)
		}
	}
}

func TestLoad_RefusesMisspelledVariable(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_JWT_SECRET", strings.Repeat("a", 64))
	t.Setenv("AUTH_COOKIE_SECUR", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "did you mean AUTH_COOKIE_SECURE") {
		t.Fatalf("err = %v, want a refusal suggesting AUTH_COOKIE_SECURE", err)
	}
}

// The generated files match the registry. Fix with `make env-docs`.
func TestEnvDocsUpToDate(t *testing.T) {
	r := Registry()
	for path, want := range map[string]string{
		EnvExamplePath:   RenderEnvExample(r),
		EnvReferencePath: RenderEnvReference(r),
	} {
		got, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatalf("%s: %v (run make env-docs)", path, err)
		}
		if string(got) != want {
			t.Errorf("api/%s is stale: run `make env-docs` in api/ and commit the result", path)
		}
	}
}

// A retired name without a replacement prints its note, never an empty
// "rename it to"; every row of the retired table keeps two cells.
func TestEnvDocsRetiredNames(t *testing.T) {
	r, err := parseEnvRegistry(envRegistryYAML)
	if err != nil {
		t.Fatal(err)
	}
	doc := RenderEnvReference(r)
	if strings.Contains(doc, "rename it to ``") {
		t.Error("a retired name without a replacement renders an empty rename")
	}
	cells := regexp.MustCompile(`(^|[^\\])\|`)
	for _, x := range retiredEnv {
		var row string
		for _, line := range strings.Split(doc, "\n") {
			if strings.HasPrefix(line, "| `"+x.Old+"` |") {
				row = line
			}
		}
		if row == "" {
			t.Errorf("%s is missing from the retired table", x.Old)
			continue
		}
		if n := len(cells.FindAllString(row, -1)); n != 3 {
			t.Errorf("%s row has %d unescaped pipes, want 3: %s", x.Old, n, row)
		}
		if x.Hint != "" && !strings.Contains(row, mdCell(x.Hint)) {
			t.Errorf("%s row lacks its note: %s", x.Old, row)
		}
		if got := x.instead(); x.Hint == "" && got != "rename it to "+x.New {
			t.Errorf("%s startup hint = %q", x.Old, got)
		}
	}
}

// A default that is prose with its own code spans is not wrapped in another
// code span: Markdown cannot nest them, and the cell rendered broken.
func TestEnvReference_DefaultCodeSpansDoNotNest(t *testing.T) {
	for in, want := range map[string]string{
		"":    "empty",
		"30s": "`30s`",
		"a|b": "`a\\|b`",
		"the minimum in `versions.yaml` (`v0.3.0`)": "the minimum in `versions.yaml` (`v0.3.0`)",
	} {
		if got := mdDefault(in); got != want {
			t.Errorf("mdDefault(%q) = %q, want %q", in, got, want)
		}
	}
	doc := RenderEnvReference(Registry())
	for _, line := range strings.Split(doc, "\n") {
		cells := strings.Split(line, " | ")
		if len(cells) < 3 || !strings.HasPrefix(cells[0], "| `") {
			continue
		}
		if def := cells[2]; strings.HasPrefix(def, "`") && strings.Count(def, "`") > 2 {
			t.Errorf("nested code span in the default of %s: %s", cells[0], def)
		}
	}
}
