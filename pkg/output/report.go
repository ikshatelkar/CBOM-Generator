package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// assetReport holds the aggregated data for one unique asset name.
// Pass and Fail are counted per individual component occurrence (use),
// not per asset name, so a name can have some passing and some failing uses.
type assetReport struct {
	Name        string
	PassUses    int    // occurrences with zero vulnerabilities
	FailUses    int    // occurrences with at least one vulnerability
	MaxSeverity string // highest severity seen across all failing uses
}

func (r *assetReport) totalUses() int { return r.PassUses + r.FailUses }

// PrintReport writes a human-readable asset table to w.
// Each unique crypto asset name is printed as one row with:
//   - total number of uses (occurrences) found in the repo
//   - PASS (no vulnerable uses) or FAIL (one or more vulnerable uses)
//
// Pass/Fail in the footer count individual uses, not asset names, so the
// Fail count matches the number of vulnerable component instances in the CBOM.
func (g *Generator) PrintReport(w io.Writer) {
	// Aggregate components by asset name, counting pass/fail per occurrence.
	byName := make(map[string]*assetReport)
	for _, comp := range g.components {
		entry, ok := byName[comp.Name]
		if !ok {
			entry = &assetReport{Name: comp.Name}
			byName[comp.Name] = entry
		}
		if len(comp.Vulnerabilities) > 0 {
			entry.FailUses++
			for _, v := range comp.Vulnerabilities {
				if severityRank(v.Severity) > severityRank(entry.MaxSeverity) {
					entry.MaxSeverity = v.Severity
				}
			}
		} else {
			entry.PassUses++
		}
	}

	if len(byName) == 0 {
		fmt.Fprintln(w, "No cryptographic assets found.")
		return
	}

	// Sort by name for deterministic output.
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	// Column widths.
	const (
		usesHeader   = "Total Uses"
		passHeader   = "Pass"
		failHeader   = "Fail"
		statusHeader = "Status"
		minNameWidth = 25
	)
	nameWidth := len("Asset")
	if nameWidth < minNameWidth {
		nameWidth = minNameWidth
	}
	for _, n := range names {
		if len(n) > nameWidth {
			nameWidth = len(n)
		}
	}
	nameWidth += 2

	usesWidth   := len(usesHeader) + 2
	passWidth   := len(passHeader) + 2
	failWidth   := len(failHeader) + 2
	totalWidth  := nameWidth + usesWidth + passWidth + failWidth + len(statusHeader) + 6

	sep := strings.Repeat("-", totalWidth)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  CBOM Asset Report")
	fmt.Fprintln(w, "  "+sep)
	fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %s\n",
		nameWidth, "Asset",
		usesWidth, usesHeader,
		passWidth, passHeader,
		failWidth, failHeader,
		statusHeader,
	)
	fmt.Fprintln(w, "  "+sep)

	// Rows + running totals.
	totalUses := 0
	passUses  := 0
	failUses  := 0
	for _, name := range names {
		entry := byName[name]
		uses := entry.totalUses()
		totalUses += uses
		passUses  += entry.PassUses
		failUses  += entry.FailUses

		status := "PASS"
		if entry.FailUses > 0 {
			status = "FAIL"
			if entry.MaxSeverity != "" {
				status = fmt.Sprintf("FAIL (%s)", strings.ToUpper(entry.MaxSeverity))
			}
		}

		fmt.Fprintf(w, "  %-*s  %-*d  %-*d  %-*d  %s\n",
			nameWidth, entry.Name,
			usesWidth, uses,
			passWidth, entry.PassUses,
			failWidth, entry.FailUses,
			status,
		)
	}

	// Footer.
	fmt.Fprintln(w, "  "+sep)
	fmt.Fprintf(w, "  Total Unique Assets: %d   Total Uses: %d   Pass: %d   Fail: %d\n\n",
		len(names), totalUses, passUses, failUses,
	)
}

// severityRank returns a numeric weight for ordering severity levels.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
