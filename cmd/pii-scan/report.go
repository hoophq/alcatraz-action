package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// defaultMarker identifies the sticky comment this action maintains on a PR
// or issue, so reruns update it instead of stacking new comments. Each scan
// mode uses its own marker id so their comments do not overwrite each other.
const defaultMarker = "alcatraz-pii-scan"

// markerFor renders the invisible HTML comment placed at the top of a report.
func markerFor(id string) string { return "<!-- " + id + " -->" }

// mask redacts a detected value so reports and annotations never re-publish
// the PII they flagged. It keeps at most the first and last two characters.
func mask(s string) string {
	runes := []rune(s)
	n := len(runes)
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	masked := n - 4
	if masked > 12 {
		masked = 12
	}
	return string(runes[:2]) + strings.Repeat("*", masked) + string(runes[n-2:])
}

// location renders where a finding was seen: "path:line", "line N" for
// file-less text input, or "-" when unknown.
func (f Finding) location() string {
	switch {
	case f.File != "":
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	case f.Line > 0:
		return fmt.Sprintf("line %d", f.Line)
	default:
		return "-"
	}
}

// writeAnnotations emits one GitHub workflow command per finding so results
// surface inline in the PR "Files changed" view and in the job log.
func writeAnnotations(w io.Writer, findings []Finding, level string) {
	for _, f := range findings {
		cmd := level
		if f.File != "" {
			cmd += fmt.Sprintf(" file=%s,line=%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "::%s::PII detected: %s %q (score %.2f)\n",
			cmd, f.EntityType, mask(f.Value), f.Score)
	}
}

// writeReport renders the markdown report posted as a PR/issue comment and
// written to the step summary. source labels what was scanned (e.g. "PR diff",
// "comment", "2 file(s)"); marker is the sticky-comment id.
func writeReport(w io.Writer, findings []Finding, source, marker string) {
	fmt.Fprintln(w, markerFor(marker))
	if len(findings) == 0 {
		fmt.Fprintf(w, "## 🪨 Alcatraz PII scan\n\nNo PII detected in %s. ✅\n", source)
		return
	}

	fmt.Fprintf(w, "## 🪨 Alcatraz PII scan\n\n**%d finding(s)** in %s.\n\n", len(findings), source)
	fmt.Fprintln(w, "| Location | Entity | Value (masked) | Score |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range findings {
		fmt.Fprintf(w, "| %s | `%s` | `%s` | %.2f |\n",
			f.location(), f.EntityType, mask(f.Value), f.Score)
	}

	fmt.Fprintf(w, "\n<details><summary>Entity breakdown</summary>\n\n%s\n</details>\n",
		entityBreakdown(findings))
	fmt.Fprintln(w, "\n> Values are masked. Review the flagged locations and remove or"+
		" redact the data, or add known-safe values to the allow list.")
}

// entityBreakdown summarizes findings per entity type, most frequent first.
func entityBreakdown(findings []Finding) string {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.EntityType]++
	}
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		if counts[types[i]] != counts[types[j]] {
			return counts[types[i]] > counts[types[j]]
		}
		return types[i] < types[j]
	})
	var b strings.Builder
	for _, t := range types {
		fmt.Fprintf(&b, "- `%s`: %d\n", t, counts[t])
	}
	return b.String()
}
