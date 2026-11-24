package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Talfaza/hyperion/internal/checks"
)

func TestAnimateOnlyOnInteractiveTerminals(t *testing.T) {
	var buf bytes.Buffer
	if animate(&buf, false) {
		t.Error("animation enabled for a non-terminal writer")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if animate(f, false) {
		t.Error("animation enabled for a regular file")
	}
	t.Setenv("CI", "true")
	if animate(os.Stderr, false) {
		t.Error("animation enabled in CI")
	}
	t.Setenv("CI", "")
	if animate(os.Stderr, true) {
		t.Error("animation enabled despite --no-progress")
	}
}

func TestProgressModel(t *testing.T) {
	var m interface{} = newProgressModel()
	pm := m.(progressModel)
	next, _ := pm.Update(checkStartedMsg{index: 3, total: 10, id: "SSH-004", title: "SSH empty passwords are rejected"})
	view := next.View().Content
	for _, want := range []string{"Scanning", " 3/10", "SSH-004"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q: %q", want, view)
		}
	}
	long := strings.Repeat("x", 200)
	next, _ = next.Update(checkStartedMsg{index: 1, total: 2, id: "X", title: long})
	if strings.Contains(next.View().Content, long) {
		t.Error("long titles must be truncated")
	}
	done, cmd := next.Update(scanDoneMsg{})
	if cmd == nil || done.View().Content != "" {
		t.Errorf("done should quit and clear the line: %q", done.View().Content)
	}
}

func fastAnimation(t *testing.T, d time.Duration) {
	t.Helper()
	old := minAnimation
	minAnimation = d
	t.Cleanup(func() { minAnimation = old })
}

func TestWithProgressPacesToMinimumDuration(t *testing.T) {
	fastAnimation(t, 300*time.Millisecond)
	start := time.Now()
	var out bytes.Buffer
	var stamps []time.Duration
	withProgress(context.Background(), &out, func(progress func(int, int, checks.Check)) int {
		for i, c := range checks.All()[:3] {
			progress(i, 3, c)
			stamps = append(stamps, time.Since(start))
		}
		return 0
	})
	if total := time.Since(start); total < 300*time.Millisecond {
		t.Errorf("animation took %v, want at least 300ms", total)
	}
	// Evenly spread: the third check starts around 2/3 of the duration.
	if stamps[2] < 150*time.Millisecond {
		t.Errorf("checks not paced: third check started at %v", stamps[2])
	}
}

func TestWithProgressCancelCutsPacingShort(t *testing.T) {
	fastAnimation(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	var out bytes.Buffer
	withProgress(ctx, &out, func(progress func(int, int, checks.Check)) int {
		progress(5, 10, checks.All()[0])
		return 0
	})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancelled scan still paced for %v", d)
	}
}

func TestWithProgressReturnsScanResult(t *testing.T) {
	fastAnimation(t, 0)
	var out bytes.Buffer
	calls := 0
	got := withProgress(context.Background(), &out, func(progress func(int, int, checks.Check)) string {
		for i, c := range checks.All()[:5] {
			progress(i, 5, c)
			calls++
		}
		return "report"
	})
	if got != "report" || calls != 5 {
		t.Fatalf("got %q after %d calls", got, calls)
	}
}

func TestWithProgressSurvivesCancelledContext(t *testing.T) {
	fastAnimation(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	got := withProgress(ctx, &out, func(func(int, int, checks.Check)) int { return 42 })
	if got != 42 {
		t.Fatalf("result lost when the display was cancelled: %d", got)
	}
}
