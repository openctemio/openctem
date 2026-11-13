package webendpoint

import "strings"

// Risk hints of a parameter, derived from its name only (never a value).
const (
	RiskSSRF     = "ssrf_candidate"
	RiskRedirect = "redirect"
	RiskIDOR     = "idor_candidate"
	RiskFilePath = "file_path"
)

// Sensitive classes of a parameter name.
const (
	SensitiveCredential = "credential"
	SensitivePII        = "pii"
	SensitiveFinancial  = "financial"
)

var (
	ssrfNames     = []string{"url", "uri", "callback", "webhook", "endpoint", "host", "proxy", "feed", "src", "dest", "target", "image_url", "link"}
	redirectNames = []string{"redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnto", "next", "continue", "goto", "back"}
	fileNames     = []string{"file", "filename", "path", "filepath", "template", "include", "page", "doc", "folder", "dir", "download"}
	credNames     = []string{"password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token", "api_key", "apikey", "key", "auth", "authorization", "session", "sessionid", "sid", "otp", "code", "signature", "sig", "client_secret", "jwt", "cookie"}
	piiNames      = []string{"email", "e-mail", "phone", "mobile", "ssn", "dob", "birthdate", "birthday", "address", "first_name", "last_name", "firstname", "lastname", "passport", "national_id"}
	finNames      = []string{"card", "card_number", "cardnumber", "cc", "ccn", "cvv", "cvc", "iban", "account_number", "routing", "pan"}
)

// normParamName lowers a name and folds '-' to '_' and the JSON pointer
// prefix away ("/order/Return-URL" -> "return_url").
func normParamName(n string) string {
	if i := strings.LastIndexByte(n, '/'); i >= 0 {
		n = n[i+1:]
	}
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		n = n[i+1:]
	}
	n = strings.Trim(n, "[]")
	return strings.ReplaceAll(strings.ToLower(n), "-", "_")
}

// ClassifyParam derives a parameter's risk hints and sensitive class from
// its name. It reads only the name: the platform never sees a value.
func ClassifyParam(name string) (risk []string, sensitive string) {
	n := normParamName(name)
	if n == "" {
		return []string{}, ""
	}
	risk = []string{}
	has := func(list []string) bool {
		for _, v := range list {
			if n == v {
				return true
			}
		}
		return false
	}
	if has(ssrfNames) || strings.HasSuffix(n, "_url") || strings.HasSuffix(n, "_uri") {
		risk = append(risk, RiskSSRF)
	}
	if has(redirectNames) {
		risk = append(risk, RiskRedirect)
	}
	if n == "id" || n == "uid" || strings.HasSuffix(n, "_id") {
		risk = append(risk, RiskIDOR)
	}
	if has(fileNames) {
		risk = append(risk, RiskFilePath)
	}
	switch {
	case has(credNames) || strings.HasSuffix(n, "_token") || strings.HasSuffix(n, "_secret") || strings.HasSuffix(n, "_password"):
		sensitive = SensitiveCredential
	case has(finNames):
		sensitive = SensitiveFinancial
	case has(piiNames):
		sensitive = SensitivePII
	}
	return risk, sensitive
}
