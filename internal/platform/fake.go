package platform

import (
	"context"
	"fmt"
	"strings"
)

// FakeRunner returns canned command output. Unregistered commands behave as
// if the binary were not installed. Used by tests.
type FakeRunner struct {
	Responses map[string]CmdResult
	Errors    map[string]error
	Calls     []string
}

func (f *FakeRunner) Set(cmdline string, stdout string, exit int) *FakeRunner {
	if f.Responses == nil {
		f.Responses = map[string]CmdResult{}
	}
	f.Responses[cmdline] = CmdResult{Stdout: []byte(stdout), ExitCode: exit}
	return f
}

// SetFailure registers a command that exits non-zero with a stderr message.
func (f *FakeRunner) SetFailure(cmdline, stderr string, exit int) *FakeRunner {
	if f.Responses == nil {
		f.Responses = map[string]CmdResult{}
	}
	f.Responses[cmdline] = CmdResult{Stderr: []byte(stderr), ExitCode: exit}
	return f
}

func (f *FakeRunner) Run(_ context.Context, name string, args ...string) (CmdResult, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.Calls = append(f.Calls, key)
	if err, ok := f.Errors[key]; ok {
		return CmdResult{}, err
	}
	if r, ok := f.Responses[key]; ok {
		return r, nil
	}
	return CmdResult{}, fmt.Errorf("%s: %w", name, ErrCommandNotFound)
}
