package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding represents a detected sensitive data leak path.
type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Source   string `json:"source"`
	Sink     string `json:"sink"`
	Variable string `json:"variable"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

var sensitiveNames = []string{
	"password", "passwd", "password_hash", "secret", "api_key",
	"apikey", "api_secret", "secret_key", "token", "access_token",
	"refresh_token", "auth_token", "credential", "private_key",
	"ssn", "social_security", "credit_card", "card_number", "cvv",
	"authorization", "database_url", "db_password", "connection_string",
}

type sinkDef struct {
	re   *regexp.Regexp
	name string
}

var sinkDefs = []sinkDef{
	{regexp.MustCompile(`\blog(?:ger|ging)?\.(?:info|debug|warn(?:ing)?|error|critical|exception|fatal)\s*\(`), "log"},
	{regexp.MustCompile(`\bprint\s*\(`), "print"},
	{regexp.MustCompile(`\b(?:jsonify|JsonResponse|JSONResponse)\s*\(`), "http-response"},
	{regexp.MustCompile(`\braise\s+\w*(?:Error|Exception)\s*\(`), "exception"},
}

func matchSensitive(s string) string {
	low := strings.ToLower(s)
	for _, n := range sensitiveNames {
		if strings.Contains(low, n) {
			return n
		}
	}
	return ""
}

func sev(sink string) string {
	if sink == "http-response" || sink == "exception" {
		return "CRITICAL"
	}
	if sink == "log" {
		return "HIGH"
	}
	return "MEDIUM"
}

func isCompare(line string, i int) bool {
	if i+1 < len(line) && line[i+1] == '=' {
		return true
	}
	if i > 0 && (line[i-1] == '!' || line[i-1] == '<' || line[i-1] == '>') {
		return true
	}
	return false
}

// Scan analyzes Python source code and returns all detected leak paths.
func Scan(filename, content string) []Finding {
	lines := strings.Split(content, "\n")
	var out []Finding
	tainted := map[string]string{}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		num := i + 1
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if ei := strings.Index(t, "="); ei > 0 && !isCompare(t, ei) {
			lhs := strings.TrimSpace(t[:ei])
			rhs := t[ei+1:]
			if !strings.ContainsAny(lhs, "([{,") {
				if strings.Contains(rhs, "os.environ") || strings.Contains(rhs, "os.getenv") {
					tainted[lhs] = "env-var"
				} else if s := matchSensitive(rhs); s != "" {
					tainted[lhs] = s
				}
			}
		}
		for _, sk := range sinkDefs {
			if !sk.re.MatchString(t) {
				continue
			}
			hit := false
			for v, src := range tainted {
				if strings.Contains(t, v) {
					out = append(out, Finding{filename, num, src, sk.name, v,
						sev(sk.name), fmt.Sprintf("'%s' (from %s) flows to %s", v, src, sk.name)})
					hit = true
				}
			}
			if !hit {
				if s := matchSensitive(t); s != "" {
					out = append(out, Finding{filename, num, s, sk.name, "(direct)",
						sev(sk.name), fmt.Sprintf("sensitive '%s' exposed via %s", s, sk.name)})
				}
			}
		}
	}
	return out
}
