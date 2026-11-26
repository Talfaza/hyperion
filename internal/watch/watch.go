// Package watch reports changes to watched files as they happen, using an
// observe-only eBPF program (fentry) that cannot block or alter anything.
//
// Milestone 0: files under /etc opened for writing, with who opened them.
package watch

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event watch bpf/watch.c -- -I/usr/include -O2 -g -Wall -Werror

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Op is the kind of file operation observed.
type Op string

const OpOpenWrite Op = "open-write"

// Event is one observed operation, attributed at the moment it happened.
type Event struct {
	Time     time.Time `json:"time"`
	Op       Op        `json:"op"`
	Path     string    `json:"path"`
	PID      uint32    `json:"pid"`
	TID      uint32    `json:"tid"`
	UID      uint32    `json:"uid"`
	LoginUID *uint32   `json:"login_uid,omitempty"` // nil when unset (no login session)
	Comm     string    `json:"comm"`
}

const auditUIDUnset = 0xffffffff

// ErrNotPrivileged is returned when the process cannot load eBPF programs.
var ErrNotPrivileged = errors.New("watch needs root (or CAP_BPF and CAP_PERFMON) to load its eBPF program")

// Run loads the eBPF program and calls emit for every event until ctx is
// done. It returns the number of events the kernel had to drop because the
// ring buffer was full.
func Run(ctx context.Context, emit func(Event)) (dropped uint64, err error) {
	if os.Geteuid() != 0 {
		return 0, ErrNotPrivileged
	}
	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return 0, fmt.Errorf("raise memlock limit: %w", err)
	}

	spec, err := loadWatch()
	if err != nil {
		return 0, fmt.Errorf("load eBPF spec: %w", err)
	}
	if err := spec.Variables["self_pid"].Set(uint32(os.Getpid())); err != nil {
		return 0, fmt.Errorf("configure eBPF program: %w", err)
	}
	var objs watchObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return 0, fmt.Errorf("load eBPF program (kernel needs BTF and fentry support, 5.10+): %w", err)
	}
	defer objs.Close()

	lnk, err := link.AttachTracing(link.TracingOptions{Program: objs.OnFileOpen})
	if err != nil {
		return 0, fmt.Errorf("attach fentry/security_file_open: %w", err)
	}
	defer lnk.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return 0, fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()
	go func() {
		<-ctx.Done()
		rd.Close() // unblocks Read
	}()

	// Kernel timestamps are CLOCK_MONOTONIC; anchor them to wall time once.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	bootOffset := time.Now().Add(-time.Duration(ts.Nano()))

	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			return readDropped(&objs), fmt.Errorf("read ring buffer: %w", err)
		}
		var raw watchEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw); err != nil {
			continue // malformed record: skip, never crash
		}
		emit(decode(raw, bootOffset))
	}
	return readDropped(&objs), nil
}

func decode(raw watchEvent, bootOffset time.Time) Event {
	e := Event{
		Time: bootOffset.Add(time.Duration(raw.TimeNs)),
		Op:   OpOpenWrite,
		Path: cString(raw.Path[:]),
		PID:  raw.Pid,
		TID:  raw.Tid,
		UID:  raw.Uid,
		Comm: cString(raw.Comm[:]),
	}
	if raw.Loginuid != auditUIDUnset {
		v := raw.Loginuid
		e.LoginUID = &v
	}
	return e
}

func readDropped(objs *watchObjects) uint64 {
	var n uint64
	_ = objs.Dropped.Lookup(uint32(0), &n)
	return n
}

// cString converts a NUL-terminated C char array (int8 in bpf2go output).
func cString(b []int8) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
