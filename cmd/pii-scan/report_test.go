package main

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abcd", "****"},
		{"jane@example.com", "ja************om"},
		{"4532015112830366", "45************66"},
		{"a-very-long-secret-value-that-keeps-going", "a-************ng"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := mask(tt.in); got != tt.want {
			t.Errorf("mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWriteReportMasksValues(t *testing.T) {
	findings := []Finding{
		{File: "user.go", Line: 11, EntityType: "CREDIT_CARD", Value: "4532015112830366", Score: 1},
		{Line: 2, EntityType: "EMAIL_ADDRESS", Value: "jane@example.com", Score: 1},
	}
	var b strings.Builder
	writeReport(&b, findings, "the PR diff", defaultMarker)
	out := b.String()

	if !strings.Contains(out, markerFor(defaultMarker)) {
		t.Error("report is missing the sticky-comment marker")
	}
	for _, raw := range []string{"4532015112830366", "jane@example.com"} {
		if strings.Contains(out, raw) {
			t.Errorf("report leaks raw PII value %q", raw)
		}
	}
	if !strings.Contains(out, "user.go:11") || !strings.Contains(out, "line 2") {
		t.Errorf("report is missing finding locations:\n%s", out)
	}
	if !strings.Contains(out, "**2 finding(s)** in the PR diff") {
		t.Errorf("report is missing the summary line:\n%s", out)
	}
}

func TestWriteReportClean(t *testing.T) {
	var b strings.Builder
	writeReport(&b, nil, "the PR diff", defaultMarker)
	if !strings.Contains(b.String(), "No PII detected") {
		t.Errorf("clean report missing all-clear message:\n%s", b.String())
	}
}

func TestWriteAnnotations(t *testing.T) {
	findings := []Finding{
		{File: "user.go", Line: 11, EntityType: "CREDIT_CARD", Value: "4532015112830366", Score: 1},
		{Line: 3, EntityType: "EMAIL_ADDRESS", Value: "jane@example.com", Score: 0.5},
	}
	var b strings.Builder
	writeAnnotations(&b, findings, "error")
	out := b.String()

	if !strings.Contains(out, "::error file=user.go,line=11::") {
		t.Errorf("missing file annotation:\n%s", out)
	}
	if !strings.Contains(out, "::error::PII detected: EMAIL_ADDRESS") {
		t.Errorf("missing file-less annotation:\n%s", out)
	}
	if strings.Contains(out, "4532015112830366") {
		t.Errorf("annotation leaks raw PII:\n%s", out)
	}
}
