package main

import (
	"encoding/json"
	"testing"
)

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"CRITICAL", 3},
		{"critical", 3},
		{"HIGH", 2},
		{"high", 2},
		{"MEDIUM", 1},
		{"medium", 1},
		{"", 0},
		{"low", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := severityLevel(tt.input)
		if got != tt.want {
			t.Errorf("severityLevel(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []Finding{
		{File: "a.py", Line: 1, Severity: "CRITICAL", Source: "password", Sink: "http-response", Variable: "pwd", Message: "critical leak"},
		{File: "b.py", Line: 2, Severity: "HIGH", Source: "api_key", Sink: "log", Variable: "key", Message: "high leak"},
		{File: "c.py", Line: 3, Severity: "MEDIUM", Source: "token", Sink: "print", Variable: "tok", Message: "medium leak"},
	}

	// Filter by CRITICAL — should return only 1
	critical := filterBySeverity(findings, "critical")
	if len(critical) != 1 {
		t.Errorf("filter critical: got %d findings, want 1", len(critical))
	}
	if len(critical) > 0 && critical[0].Severity != "CRITICAL" {
		t.Errorf("filter critical: got severity %s, want CRITICAL", critical[0].Severity)
	}

	// Filter by HIGH — should return CRITICAL + HIGH = 2
	high := filterBySeverity(findings, "high")
	if len(high) != 2 {
		t.Errorf("filter high: got %d findings, want 2", len(high))
	}

	// Filter by MEDIUM — should return all 3
	medium := filterBySeverity(findings, "medium")
	if len(medium) != 3 {
		t.Errorf("filter medium: got %d findings, want 3", len(medium))
	}

	// Empty threshold — should return all
	all := filterBySeverity(findings, "")
	if len(all) != 3 {
		t.Errorf("filter empty: got %d findings, want 3", len(all))
	}
}

func TestFilterBySeverityEmpty(t *testing.T) {
	var findings []Finding
	result := filterBySeverity(findings, "high")
	if result != nil {
		t.Errorf("filter empty input: got %v, want nil", result)
	}
}

func TestToSARIFEmpty(t *testing.T) {
	report := toSARIF(nil)
	if report.Version != "2.1.0" {
		t.Errorf("SARIF version = %s, want 2.1.0", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
	}
	if report.Runs[0].Tool.Driver.Name != "LeakTrace" {
		t.Errorf("tool name = %s, want LeakTrace", report.Runs[0].Tool.Driver.Name)
	}
}

func TestToSARIFWithFindings(t *testing.T) {
	findings := []Finding{
		{File: "app/views.py", Line: 42, Severity: "CRITICAL", Source: "password", Sink: "http-response", Variable: "pwd", Message: "password in response"},
		{File: "app/utils.py", Line: 17, Severity: "HIGH", Source: "api_key", Sink: "log", Variable: "key", Message: "api_key in log"},
	}

	report := toSARIF(findings)

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Verify first result
	r0 := run.Results[0]
	if r0.RuleID != "leaktrace/password-to-http-response" {
		t.Errorf("result[0] ruleId = %s, want leaktrace/password-to-http-response", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("result[0] level = %s, want error", r0.Level)
	}
	if len(r0.Locations) != 1 {
		t.Fatalf("result[0] expected 1 location, got %d", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "app/views.py" {
		t.Errorf("result[0] uri = %s, want app/views.py", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("result[0] startLine = %d, want 42", r0.Locations[0].PhysicalLocation.Region.StartLine)
	}

	// Verify second result
	r1 := run.Results[1]
	if r1.RuleID != "leaktrace/api_key-to-log" {
		t.Errorf("result[1] ruleId = %s, want leaktrace/api_key-to-log", r1.RuleID)
	}
	if r1.Level != "warning" {
		t.Errorf("result[1] level = %s, want warning", r1.Level)
	}
}

func TestToSARIFDuplicateRules(t *testing.T) {
	findings := []Finding{
		{File: "a.py", Line: 1, Severity: "HIGH", Source: "password", Sink: "log", Variable: "p1", Message: "leak 1"},
		{File: "b.py", Line: 5, Severity: "HIGH", Source: "password", Sink: "log", Variable: "p2", Message: "leak 2"},
	}

	report := toSARIF(findings)
	run := report.Runs[0]

	// Same source-sink pair should produce only 1 rule
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(run.Tool.Driver.Rules))
	}
	// But 2 results
	if len(run.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(run.Results))
	}
}

func TestSARIFJSONValid(t *testing.T) {
	findings := []Finding{
		{File: "test.py", Line: 10, Severity: "CRITICAL", Source: "secret", Sink: "http-response", Variable: "s", Message: "secret leak"},
	}

	report := toSARIF(findings)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal SARIF: %v", err)
	}

	// Verify it's valid JSON by unmarshalling back
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check required SARIF fields
	if parsed["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", parsed["version"])
	}
	if parsed["$schema"] == nil {
		t.Error("SARIF $schema is missing")
	}
}

func TestSarifLevelFromSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "warning"},
		{"MEDIUM", "note"},
		{"LOW", "note"},
	}
	for _, tt := range tests {
		got := sarifLevelFromSeverity(tt.severity)
		if got != tt.want {
			t.Errorf("sarifLevelFromSeverity(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}
