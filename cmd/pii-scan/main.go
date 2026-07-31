// Command pii-scan detects PII in PR diffs, files, and free text using
// github.com/hoophq/alcatraz, and reports findings in the formats GitHub
// Actions consumes: workflow annotations, a markdown report (for PR/issue
// comments and the step summary), and a findings count in GITHUB_OUTPUT.
//
// Modes:
//
//	-mode diff   read a unified diff on stdin, scan added lines only
//	-mode files  scan the files given as positional arguments, line by line
//	-mode text   read free text on stdin (a PR comment or issue body)
//
// The command always exits 0 when the scan itself succeeds enforcement
// (failing the job) is the caller's decision, driven by the findings output.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pii-scan:", err)
		os.Exit(2)
	}
}

func run() error {
	mode := flag.String("mode", "diff", "input mode: diff, files, or text")
	threshold := flag.Float64("threshold", 0.4, "minimum confidence score in [0,1]")
	entities := flag.String("entities", "", "comma-separated entity types to restrict to (empty = all)")
	ignore := flag.String("ignore", "DATE_TIME,URL", "comma-separated entity types to drop as noise")
	allowlistFile := flag.String("allowlist-file", "", "file with allowed values, one per line")
	exclude := flag.String("exclude", "", "comma-separated glob patterns of diff paths to skip")
	reportPath := flag.String("report", "", "write the markdown report to this path")
	source := flag.String("source", "", "label for what was scanned, used in the report")
	marker := flag.String("marker", defaultMarker, "sticky-comment marker id embedded in the report")
	level := flag.String("level", "error", "annotation level: error, warning, or notice")
	useContext := flag.Bool("context", true, "score a match higher when a word naming its entity type precedes it (-context=false for pattern-only scores)")
	flag.Parse()

	allowList, err := readAllowlist(*allowlistFile)
	if err != nil {
		return err
	}
	s := newScanner(*threshold, splitList(*entities), splitList(*ignore), allowList)
	s.exclude = splitList(*exclude)
	if !*useContext {
		s.disableContext()
	}

	var findings []Finding
	switch *mode {
	case "diff":
		findings, err = s.scanDiff(os.Stdin)
	case "text":
		findings, err = s.scanText(os.Stdin)
	case "files":
		if flag.NArg() == 0 {
			return fmt.Errorf("mode files requires at least one file argument")
		}
		for _, path := range flag.Args() {
			fs, ferr := s.scanFile(path)
			if ferr != nil {
				return ferr
			}
			findings = append(findings, fs...)
		}
	default:
		return fmt.Errorf("unknown mode %q (want diff, files, or text)", *mode)
	}
	if err != nil {
		return err
	}

	writeAnnotations(os.Stdout, findings, *level)
	fmt.Printf("pii-scan: %d finding(s)\n", len(findings))

	label := *source
	if label == "" {
		label = defaultSource(*mode, flag.Args())
	}
	if *reportPath != "" {
		f, err := os.Create(*reportPath)
		if err != nil {
			return err
		}
		writeReport(f, findings, label, *marker)
		if err := f.Close(); err != nil {
			return err
		}
	}
	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		if err := appendReport(summary, findings, label, *marker); err != nil {
			return err
		}
	}
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		if err := appendLine(out, fmt.Sprintf("findings=%d", len(findings))); err != nil {
			return err
		}
	}
	return nil
}

func defaultSource(mode string, files []string) string {
	switch mode {
	case "diff":
		return "the PR diff"
	case "text":
		return "the analyzed text"
	default:
		return fmt.Sprintf("%d file(s): %s", len(files), strings.Join(files, ", "))
	}
}

// readAllowlist loads one allowed value per line, skipping blanks and
// #-comments.
func readAllowlist(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	var values []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}
	return values, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func appendReport(path string, findings []Finding, source, marker string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	writeReport(f, findings, source, marker)
	return f.Close()
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, line)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
