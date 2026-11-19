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
