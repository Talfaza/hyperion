package profiles

import (
	"strings"
	"testing"

	"github.com/Talfaza/hyperion/internal/checks"
)

func TestBuiltinProfilesAreValid(t *testing.T) {
	if err := Validate(checks.All()); err != nil {
		t.Fatal(err)
	}
	if Names()[0] != Default {
		t.Errorf("default profile should be listed first: %v", Names())
	}
	if p, err := Lookup(Default); err != nil || len(p.NotApplicable)+len(p.Raise) != 0 {
		t.Errorf("the default server profile must be the unmodified baseline: %+v %v", p, err)
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, err := Lookup("laptop"); err == nil || !strings.Contains(err.Error(), "workstation") {
		t.Errorf("unknown profile should list the available ones: %v", err)
	}
}

func TestValidateRejectsUnsafeProfiles(t *testing.T) {
	cases := map[string]Profile{
		"critical not applicable": {Name: "x", NotApplicable: map[string]string{"AUTH-006": "because"}},
		"unknown check":           {Name: "x", NotApplicable: map[string]string{"NOPE-001": "because"}},
		"empty reason":            {Name: "x", NotApplicable: map[string]string{"KRN-006": "  "}},
		"lowered severity":        {Name: "x", Raise: map[string]Raise{"SSH-002": {checks.Low, "because"}}},
		"same severity":           {Name: "x", Raise: map[string]Raise{"KRN-006": {checks.Medium, "because"}}},
		"raised to critical":      {Name: "x", Raise: map[string]Raise{"KRN-006": {checks.Critical, "because"}}},
		"raise without reason":    {Name: "x", Raise: map[string]Raise{"KRN-006": {checks.High, ""}}},
		"both raised and n/a": {Name: "x",
			NotApplicable: map[string]string{"KRN-006": "because"},
			Raise:         map[string]Raise{"KRN-006": {checks.High, "because"}}},
	}
	for name, p := range cases {
		if err := validate(map[string]Profile{"x": p}, checks.All()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolve(t *testing.T) {
	p, err := Resolve("workstation")
	if err != nil || p.Name != "workstation" {
		t.Fatalf("single: %+v %v", p.Name, err)
	}
	a, err := Resolve("workstation,container-host")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Resolve(" container-host , workstation ")
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "container-host+workstation" || b.Name != a.Name {
		t.Errorf("combined names should be sorted and stable: %q %q", a.Name, b.Name)
	}
	for spec, why := range map[string]string{
		"server,workstation":      "server cannot be combined",
		"workstation,workstation": "duplicate",
		"workstation,laptop":      "unknown",
		"workstation,":            "empty name",
		"":                        "empty",
	} {
		if _, err := Resolve(spec); err == nil {
			t.Errorf("%q accepted (%s)", spec, why)
		}
	}
}

func TestCombineBuiltins(t *testing.T) {
	ws, _ := Lookup("workstation")
	ch, _ := Lookup("container-host")
	c, err := Combine([]string{"workstation", "container-host"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfile(c, checks.All()); err != nil {
		t.Fatalf("combination breaks the rules: %v", err)
	}
	// Union of not-applicable checks.
	for _, p := range []Profile{ws, ch} {
		for id := range p.NotApplicable {
			if _, ok := c.NotApplicable[id]; !ok {
				t.Errorf("%s n/a in %s but not in the combination", id, p.Name)
			}
		}
		for id, r := range p.Raise {
			if got, ok := c.Raise[id]; !ok || got.To < r.To {
				t.Errorf("%s raise lost in the combination", id)
			}
		}
	}
	// MNT-004 is n/a in both: both reasons are kept, attributed.
	if r := c.NotApplicable["MNT-004"]; !strings.Contains(r, "workstation:") || !strings.Contains(r, "container-host:") {
		t.Errorf("MNT-004 reasons should name both profiles: %q", r)
	}
	if got, want := len(c.NotApplicable)+len(c.Raise), 10; got != want {
		t.Errorf("combination adjusts %d checks, want %d", got, want)
	}
}

func TestMergeConflictsAreStrict(t *testing.T) {
	a := Profile{Name: "a",
		NotApplicable: map[string]string{"KRN-006": "a does not need it", "NET-002": "a does not need it"},
		Raise:         map[string]Raise{"MNT-004": {checks.Medium, "a cares"}}}
	b := Profile{Name: "b",
		Raise: map[string]Raise{"KRN-006": {checks.High, "b cares a lot"}, "MNT-004": {checks.High, "b cares more"}}}
	m := merge([]Profile{a, b})

	// Raised by b, n/a in a: the stricter outcome wins, the check stays.
	if _, na := m.NotApplicable["KRN-006"]; na {
		t.Error("a check raised by one profile must not be skipped by another")
	}
	if m.Raise["KRN-006"].To != checks.High {
		t.Errorf("KRN-006 raise %v, want high", m.Raise["KRN-006"].To)
	}
	// The highest raise wins, attributed to its profile.
	if r := m.Raise["MNT-004"]; r.To != checks.High || !strings.HasPrefix(r.Reason, "b:") {
		t.Errorf("MNT-004 raise %+v, want high from b", r)
	}
	if _, ok := m.NotApplicable["NET-002"]; !ok {
		t.Error("NET-002 n/a lost")
	}
	if m.Name != "a+b" {
		t.Errorf("name %q", m.Name)
	}
}
