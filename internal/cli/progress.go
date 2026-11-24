package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"

	"github.com/Talfaza/hyperion/internal/checks"
)

// animate reports whether a live progress display belongs on w: only an
// interactive terminal, never in CI, a dumb terminal or when disabled.
// Scripts and pipes keep the exact same output as before.
func animate(w io.Writer, disabled bool) bool {
	if disabled || os.Getenv("CI") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}

// minAnimation is how long the progress display lasts at least. A scan takes
// well under a second, too fast to read; checks are paced evenly across this
// time so the bar fills smoothly. It only applies when the animation is shown
// (never to pipes, CI or --no-progress), and cancelling the scan cuts it short.
var minAnimation = 2 * time.Second

// pacer delays check i of total until its share of minAnimation has passed.
type pacer struct {
	ctx   context.Context
	start time.Time
	min   time.Duration
}

func (p pacer) wait(i, total int) {
	if total <= 0 || p.min <= 0 {
		return
	}
	target := p.start.Add(p.min * time.Duration(i) / time.Duration(total))
	if d := time.Until(target); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-p.ctx.Done():
		}
	}
}

type checkStartedMsg struct {
	index, total int
	id, title    string
}

type scanDoneMsg struct{}

var (
	progressLabel = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	progressFaint = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

// progressModel draws one line: spinner, bar, count and the running check.
type progressModel struct {
	spinner  spinner.Model
	bar      progress.Model
	index    int
	total    int
	current  string
	finished bool
}

func newProgressModel() progressModel {
	return progressModel{
		spinner: spinner.New(spinner.WithSpinner(spinner.Dot),
			spinner.WithStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("5")))),
		bar: progress.New(progress.WithDefaultBlend(), progress.WithWidth(28), progress.WithoutPercentage()),
	}
}

func (m progressModel) Init() tea.Cmd { return m.spinner.Tick }

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case checkStartedMsg:
		m.index, m.total = msg.index, msg.total
		m.current = msg.id + "  " + msg.title
		return m, nil
	case scanDoneMsg:
		m.finished = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m progressModel) View() tea.View {
	if m.finished {
		return tea.NewView("") // leave the terminal clean for the report
	}
	pct := 0.0
	if m.total > 0 {
		pct = float64(m.index) / float64(m.total)
	}
	current := m.current
	if len(current) > 60 {
		current = current[:59] + "…"
	}
	return tea.NewView(fmt.Sprintf("%s %s %s %s  %s",
		m.spinner.View(),
		progressLabel.Render("Scanning"),
		m.bar.ViewAs(pct),
		progressFaint.Render(fmt.Sprintf("%2d/%d", m.index, m.total)),
		progressFaint.Render(current)))
}

// withProgress runs scan while a progress line animates on w. The program
// never reads input and leaves signals to the CLI's own handler, so Ctrl+C
// still cancels ctx and the scan stops cleanly.
func withProgress[T any](ctx context.Context, w io.Writer, scan func(progress func(int, int, checks.Check)) T) T {
	p := tea.NewProgram(newProgressModel(),
		tea.WithContext(ctx),
		tea.WithOutput(w),
		tea.WithInput(nil),
		tea.WithoutSignalHandler(),
	)
	result := make(chan T, 1)
	pace := pacer{ctx: ctx, start: time.Now(), min: minAnimation}
	go func() {
		total := 0
		res := scan(func(i, n int, c checks.Check) {
			total = n
			pace.wait(i, n)
			p.Send(checkStartedMsg{index: i, total: n, id: c.ID, title: c.Title})
		})
		pace.wait(total, total) // let the last check's slot elapse too
		result <- res
		p.Send(scanDoneMsg{})
	}()
	// A display failure must never lose the scan: the result is read from
	// the channel either way.
	_, _ = p.Run()
	return <-result
}
