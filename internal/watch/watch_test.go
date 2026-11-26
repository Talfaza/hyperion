package watch

import (
	"math"
	"testing"
	"time"
)

func TestCString(t *testing.T) {
	cases := map[string][]uint8{
		"":         {0, 'x'},
		"bash":     {'b', 'a', 's', 'h', 0, 'z', 'z'},
		"no-nul":   []uint8("no-nul"),
		"/etc/ssh": append([]uint8("/etc/ssh"), make([]uint8, 10)...),
	}
	for want, in := range cases {
		if got := cString(in); got != want {
			t.Errorf("cString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecode(t *testing.T) {
	boot := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	var raw watchEvent
	raw.TimeNs = uint64(5 * time.Second)
	raw.Pid, raw.Tid, raw.Uid, raw.Loginuid = 42, 43, 0, 1000
	copy(raw.Comm[:], "sed")
	copy(raw.Path[:], "/etc/hosts")

	e, ok := decode(raw, boot)
	if !ok || e.Path != "/etc/hosts" || e.Comm != "sed" || e.PID != 42 || e.UID != 0 || e.Op != OpOpenWrite {
		t.Fatalf("decode = %+v, %v", e, ok)
	}
	if !e.Time.Equal(boot.Add(5 * time.Second)) {
		t.Errorf("time %v", e.Time)
	}
	if e.LoginUID == nil || *e.LoginUID != 1000 {
		t.Errorf("login uid %v", e.LoginUID)
	}

	raw.Loginuid = auditUIDUnset
	if e, _ := decode(raw, boot); e.LoginUID != nil {
		t.Error("unset login uid should decode to nil")
	}

	raw.TimeNs = math.MaxInt64 + 1
	if _, ok := decode(raw, boot); ok {
		t.Error("impossible timestamp accepted")
	}
}
