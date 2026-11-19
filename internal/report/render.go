package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/profiles"
)

// ANSI palette colors adapt to the user's terminal theme, so the output
// reads well on both light and dark backgrounds.
var (
	colGreen  = lipgloss.Color("2")
	colRed    = lipgloss.Color("1")
	colYellow = lipgloss.Color("3")
	colBlue   = lipgloss.Color("4")
	colPurple = lipgloss.Color("5")
	colCyan   = lipgloss.Color("6")
	colGray   = lipgloss.Color("8")

	sBold   = lipgloss.NewStyle().Bold(true)
	sFaint  = lipgloss.NewStyle().Foreground(colGray)
	sTitle  = lipgloss.NewStyle().Bold(true).Foreground(colPurple)
	sLabel  = lipgloss.NewStyle().Foreground(colGray).Width(10)
	sCode   = lipgloss.NewStyle().Foreground(colCyan)
	sHeader = lipgloss.NewStyle().Bold(true).Foreground(colGray).Padding(0, 1)
	sCell   = lipgloss.NewStyle().Padding(0, 1)
)

func statusStyle(s checks.Status) (string, lipgloss.Style) {
	switch s {
	case checks.Pass:
		return "✓ PASS", lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	case checks.Fail:
		return "✗ FAIL", lipgloss.NewStyle().Foreground(colRed).Bold(true)
	case checks.Skip:
		return "○ SKIP", lipgloss.NewStyle().Foreground(colGray)
	case checks.Excepted:
		return "◇ EXCEPT", lipgloss.NewStyle().Foreground(colCyan).Bold(true)
	default:
		return "! ERR ", lipgloss.NewStyle().Foreground(colYellow).Bold(true)
	}
}

func severityStyle(s checks.Severity) lipgloss.Style {
	switch s {
	case checks.Critical:
		return lipgloss.NewStyle().Foreground(colRed).Bold(true)
	case checks.High:
		return lipgloss.NewStyle().Foreground(colRed)
	case checks.Medium:
		return lipgloss.NewStyle().Foreground(colYellow)
	default:
		return lipgloss.NewStyle().Foreground(colBlue)
	}
}

func scoreColor(score int) lipgloss.Style {
	switch {
	case score >= 80:
		return lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	case score >= 50:
		return lipgloss.NewStyle().Foreground(colYellow).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(colRed).Bold(true)
	}
}

func scoreBar(score, width int) string {
	filled := score * width / 100
	return scoreColor(score).Render(strings.Repeat("█", filled)) +
		sFaint.Render(strings.Repeat("░", width-filled))
}

type TableOptions struct {
	Width      int  // terminal width; 0 means 100
	FailedOnly bool // hide passing and skipped checks from the table
}

// WriteTable renders the report for humans. w should be a colorprofile
// writer so colors are downsampled or stripped (NO_COLOR, pipes).
func WriteTable(w io.Writer, r Report, opt TableOptions) error {
	width := opt.Width
	if width <= 0 {
		width = 100
	}
	width = min(width, 120)

	var b strings.Builder
	b.WriteString(header(r, width))
	b.WriteString("\n\n")
	b.WriteString(findingsTable(r.Findings, opt.FailedOnly))
	b.WriteString("\n")

	if details := problemDetails(r.Findings, width); details != "" {
		b.WriteString("\n")
		b.WriteString(details)
	}
	if r.Exceptions != nil && len(r.Exceptions.Unused) > 0 {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(colYellow).Render(fmt.Sprintf(
			"⚠  Unused exceptions (check passed, errored or was not run): %s. Remove them from %s.",
			strings.Join(r.Exceptions.Unused, ", "), Sanitize(r.Exceptions.Path))))
		b.WriteString("\n")
	}
	if !r.RunningAsRoot {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(colYellow).Render(
			"⚠  Not running as root: checks that read protected files report errors. Re-run with sudo for a complete score."))
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func header(r Report, width int) string {
	host := Sanitize(r.Host.Hostname)
	if host == "" {
		host = "unknown host"
	}
	osName := Sanitize(r.Host.OS)
	if osName == "" {
		osName = "unknown OS"
	}
	meta := sFaint.Render(fmt.Sprintf("%s · %s · kernel %s", host, osName, Sanitize(r.Host.Kernel)))

	score := scoreColor(r.Score).Render(fmt.Sprintf("%d", r.Score)) + sFaint.Render("/100")
	scoreLine := sBold.Render("Score ") + score + "  " + scoreBar(r.Score, 30)
	// Never show an adjusted score without the unadjusted ones.
	if r.Summary.Excepted > 0 {
		scoreLine += sFaint.Render("  strict ") + scoreColor(r.ScoreStrict).Render(fmt.Sprintf("%d", r.ScoreStrict))
	}
	if r.Profile != "" && r.Profile != "server" {
		scoreLine += sFaint.Render("  full baseline ") + scoreColor(r.ScoreBaseline).Render(fmt.Sprintf("%d", r.ScoreBaseline))
	}
	parts := []string{
		lipgloss.NewStyle().Foreground(colGreen).Render(fmt.Sprintf("✓ %d passed", r.Summary.Pass)),
		lipgloss.NewStyle().Foreground(colRed).Render(fmt.Sprintf("✗ %d failed", r.Summary.Fail)),
		lipgloss.NewStyle().Foreground(colYellow).Render(fmt.Sprintf("! %d errors", r.Summary.Error)),
		sFaint.Render(fmt.Sprintf("○ %d skipped", r.Summary.Skip)),
	}
	if r.Summary.Excepted > 0 {
		parts = append(parts, lipgloss.NewStyle().Foreground(colCyan).Render(fmt.Sprintf("◇ %d excepted", r.Summary.Excepted)))
	}
	counts := strings.Join(parts, "   ")

	lines := []string{
		sTitle.Render("HYPERION TRACE") + sFaint.Render("  ·  posture scan"),
		meta,
	}
	if r.Profile != "" {
		changed := 0
		for _, f := range r.Findings {
			if f.Profile != nil {
				changed++
			}
		}
		lines = append(lines, sFaint.Render(fmt.Sprintf("profile %s (%d checks adjusted)", r.Profile, changed)))
	}
	if r.Exceptions != nil {
		lines = append(lines, sFaint.Render(fmt.Sprintf("exceptions %s (sha256 %s)", Sanitize(r.Exceptions.Path), shortHash(r.Exceptions.SHA256))))
	}
	lines = append(lines, "", scoreLine, counts)
	body := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colPurple).
		Padding(0, 2).
		Width(min(width, 90)).
		Render(body)
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func findingsTable(findings []Finding, failedOnly bool) string {
	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderColumn(false).
		BorderStyle(sFaint).
		Headers("STATUS", "SEVERITY", "ID", "CHECK", "CONTROL")

	var styles [][]lipgloss.Style
	for _, f := range findings {
		if failedOnly && (f.Status == checks.Pass || f.Status == checks.Skip) {
			continue
		}
		label, st := statusStyle(f.Status)
		title := f.Title
		if f.Status == checks.Skip {
			title = sFaint.Render(title)
		}
		t.Row(label, f.Severity.String(), f.ID, title, f.Control)
		styles = append(styles, []lipgloss.Style{
			st, severityStyle(f.Severity), sFaint, lipgloss.NewStyle(), sFaint,
		})
	}
	if len(styles) == 0 {
		return lipgloss.NewStyle().Foreground(colGreen).Render("  No failed checks.")
	}
	t.StyleFunc(func(row, col int) lipgloss.Style {
		if row == table.HeaderRow {
			return sHeader
		}
		return styles[row][col].Padding(0, 1)
	})
	return t.Render()
}

// problemDetails explains every failed or errored check with what was found
// and how to fix it. Errors with an identical cause (e.g. every SSH check
// failing to read sshd_config) are collapsed into one block.
func problemDetails(findings []Finding, width int) string {
	indent := lipgloss.NewStyle().MarginLeft(4)
	wrap := lipgloss.NewStyle().Width(max(width-14, 30))
	row := func(label, text string) string {
		return indent.Render(lipgloss.JoinHorizontal(lipgloss.Top, sLabel.Render(label), wrap.Render(text)))
	}

	var blocks []string
	errorGroups := map[string]int{} // detail -> index in blocks
	var groupIDs [][]string

	for _, f := range findings {
		if f.Status != checks.Fail && f.Status != checks.Error && f.Status != checks.Excepted {
			continue
		}
		detail := Sanitize(f.Detail)
		if f.Status == checks.Error {
			if i, ok := errorGroups[detail]; ok {
				groupIDs[i] = append(groupIDs[i], f.ID)
				continue
			}
		}

		label, st := statusStyle(f.Status)
		lines := []string{st.Render(strings.Fields(label)[0]) + " " + sBold.Render(f.ID) + "  " + f.Title + "  " +
			severityStyle(f.Severity).Render(f.Severity.String()) + sFaint.Render(" · "+f.Control)}
		if detail != "" {
			kind := "found"
			if f.Status == checks.Error {
				kind = "error"
			}
			lines = append(lines, row(kind, detail))
		}
		if e := f.Exception; e != nil {
			state := "until " + e.Expires
			if e.Expired {
				state = "EXPIRED on " + e.Expires
			}
			lines = append(lines,
				row("accepted", Sanitize(e.Reason)),
				row("control", Sanitize(e.CompensatingControl)),
				row("approved", Sanitize(e.ApprovedBy)+sFaint.Render(", "+state)))
		}
		if f.Remediation != "" {
			lines = append(lines, row("fix", highlightCode(f.Remediation)))
		}
		blocks = append(blocks, strings.Join(lines, "\n"))
		groupIDs = append(groupIDs, []string{f.ID})
		if f.Status == checks.Error {
			errorGroups[detail] = len(blocks) - 1
		}
	}
	if len(blocks) == 0 {
		return ""
	}
	for i, ids := range groupIDs {
		if len(ids) > 1 {
			blocks[i] += "\n" + row("also", sFaint.Render(strings.Join(ids[1:], ", ")+" (same error)"))
		}
	}
	return sBold.Render("Findings") + "\n\n" + strings.Join(blocks, "\n\n") + "\n"
}

// highlightCode colors `backticked` spans in remediation text.
func highlightCode(s string) string {
	parts := strings.Split(s, "`")
	for i := 1; i < len(parts); i += 2 {
		parts[i] = sCode.Render(parts[i])
	}
	return strings.Join(parts, "")
}

// WriteJSON writes the report as indented JSON. encoding/json escapes all
// control characters, so host-derived strings are safe in this format.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteChecks lists the available checks.
func WriteChecks(w io.Writer, list []checks.Check) error {
	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderColumn(false).
		BorderStyle(sFaint).
		Headers("ID", "SEVERITY", "CATEGORY", "CONTROL", "CHECK")
	for _, c := range list {
		t.Row(c.ID, c.Severity.String(), c.Category, c.Control, c.Title)
	}
	t.StyleFunc(func(row, col int) lipgloss.Style {
		if row == table.HeaderRow {
			return sHeader
		}
		switch col {
		case 0:
			return sCell.Bold(true)
		case 1:
			return severityStyle(list[row].Severity).Padding(0, 1)
		case 2, 3:
			return sFaint.Padding(0, 1)
		}
		return sCell
	})
	_, err := fmt.Fprintf(w, "%s\n\n%s\n", t.Render(), sFaint.Render(fmt.Sprintf("%d checks", len(list))))
	return err
}

// WriteProfiles lists each profile and exactly what it changes.
func WriteProfiles(w io.Writer, list []profiles.Profile) error {
	var b strings.Builder
	for i, p := range list {
		if i > 0 {
			b.WriteString("\n")
		}
		name := sTitle.Render(p.Name)
		if p.Name == profiles.Default {
			name += sFaint.Render("  (default)")
		}
		b.WriteString(name + "\n" + sFaint.Render(p.Description) + "\n")
		if len(p.NotApplicable) == 0 && len(p.Raise) == 0 {
			b.WriteString("  full baseline, nothing adjusted\n")
			continue
		}
		ids := make([]string, 0, len(p.NotApplicable))
		for id := range p.NotApplicable {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			b.WriteString(fmt.Sprintf("  %s %s  %s\n", sFaint.Render("not applicable"), sBold.Render(id), p.NotApplicable[id]))
		}
		ids = ids[:0]
		for id := range p.Raise {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			r := p.Raise[id]
			b.WriteString(fmt.Sprintf("  %s %s  to %s: %s\n", sFaint.Render("raised        "), sBold.Render(id), severityStyle(r.To).Render(r.To.String()), r.Reason))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
