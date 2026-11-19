package exceptions

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Talfaza/hyperion/internal/checks"
)

var today = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func entry(check, expires string) string {
	return `{"check":"` + check + `","reason":"Docker host needs IP forwarding","compensating_control":"nftables default-deny forward chain","approved_by":"Security officer","expires":"` + expires + `"}`
}

func doc(entries ...string) []byte {
	return []byte(`{"version":1,"exceptions":[` + strings.Join(entries, ",") + `]}`)
}

func TestParseValid(t *testing.T) {
	set, err := Parse(doc(entry("KRN-006", "2027-06-30"), entry("CRY-001", "2026-12-31")), checks.All(), today)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := set.Lookup("KRN-006")
	if !ok || e.Expired(today) {
		t.Fatalf("KRN-006 should be a valid, unexpired exception: %+v %v", e, ok)
	}
	if len(set.SHA256) != 64 {
		t.Errorf("sha256 %q", set.SHA256)
	}
	if _, ok := set.Lookup("SSH-001"); ok {
		t.Error("lookup of a non-excepted check succeeded")
	}
}

func TestExpiryIsEndOfDayUTC(t *testing.T) {
	set, err := Parse(doc(entry("KRN-006", "2026-11-19")), checks.All(), today)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := set.Lookup("KRN-006")
	if e.Expired(time.Date(2026, 11, 19, 23, 59, 0, 0, time.UTC)) {
		t.Error("exception should be valid through its expiry day")
	}
	if !e.Expired(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Error("exception should expire after its expiry day")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string][]byte{
		"not json":         []byte(`version: 1`),
		"trailing data":    []byte(`{"version":1,"exceptions":[]} {"version":1}`),
		"unknown field":    []byte(`{"version":1,"exceptions":[],"allow_all":true}`),
		"unknown entry fl": doc(strings.Replace(entry("KRN-006", "2027-01-01"), `"check"`, `"severity":"low","check"`, 1)),
		"wrong version":    []byte(`{"version":2,"exceptions":[]}`),
		"missing version":  []byte(`{"exceptions":[]}`),
		"unknown check":    doc(entry("KRN-999", "2027-01-01")),
		"missing check":    doc(entry("", "2027-01-01")),
		"critical check":   doc(entry("AUTH-006", "2027-01-01")),
		"duplicate":        doc(entry("KRN-006", "2027-01-01"), entry("KRN-006", "2027-02-01")),
		"bad date":         doc(entry("KRN-006", "30/06/2027")),
		"more than a year": doc(entry("KRN-006", "2028-01-01")),
		"short reason":     doc(strings.Replace(entry("KRN-006", "2027-01-01"), "Docker host needs IP forwarding", "ok", 1)),
		"blank control":    doc(strings.Replace(entry("KRN-006", "2027-01-01"), "nftables default-deny forward chain", "          ", 1)),
		"no approver":      doc(strings.Replace(entry("KRN-006", "2027-01-01"), "Security officer", "", 1)),
		"control char":     doc(strings.Replace(entry("KRN-006", "2027-01-01"), "Docker host", `Docker\u001b[2J host`, 1)),
		"bidi char":        doc(strings.Replace(entry("KRN-006", "2027-01-01"), "Docker host", `Docker\u202e host`, 1)),
		"huge text":        doc(strings.Replace(entry("KRN-006", "2027-01-01"), "Docker host", strings.Repeat("x", 600), 1)),
	}
	for name, data := range cases {
		if _, err := Parse(data, checks.All(), today); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEveryCriticalCheckIsRejected(t *testing.T) {
	for _, c := range checks.All() {
		if c.Severity != checks.Critical {
			continue
		}
		if _, err := Parse(doc(entry(c.ID, "2027-01-01")), checks.All(), today); err == nil || !strings.Contains(err.Error(), "critical") {
			t.Errorf("%s: critical check accepted as an exception (%v)", c.ID, err)
		}
	}
}

func TestParseAllowsAlreadyExpiredEntries(t *testing.T) {
	// An expired entry is valid file content; the report turns it back into
	// a failure rather than refusing the whole file.
	set, err := Parse(doc(entry("KRN-006", "2026-01-31")), checks.All(), today)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := set.Lookup("KRN-006"); !e.Expired(today) {
		t.Error("entry should be expired")
	}
}

func TestLoadMissingDefaultVsExplicit(t *testing.T) {
	missing := t.TempDir() + "/none.json"
	uid := os.Geteuid()
	if set, err := Load(missing, false, uid, checks.All(), today); err != nil || set != nil {
		t.Errorf("missing default file: want (nil, nil), got (%v, %v)", set, err)
	}
	// A default path whose directory doesn't exist (no /etc/hyperion) is fine too.
	if set, err := Load(t.TempDir()+"/nodir/exceptions.json", false, uid, checks.All(), today); err != nil || set != nil {
		t.Errorf("missing default directory: want (nil, nil), got (%v, %v)", set, err)
	}
	if _, err := Load(missing, true, uid, checks.All(), today); err == nil {
		t.Error("missing explicit file should be an error")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(doc(entry("KRN-006", "2027-06-30")))
	f.Add([]byte(`{"version":1,"exceptions":[{"check":"x"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := Parse(data, checks.All(), today)
		if err != nil {
			return
		}
		for _, id := range set.IDs() {
			for _, c := range checks.All() {
				if c.ID == id && c.Severity == checks.Critical {
					t.Fatalf("critical check %s accepted", id)
				}
			}
		}
	})
}
