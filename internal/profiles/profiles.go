// Package profiles defines baseline variants for classes of machines.
//
// A profile can only do two things, both visible in the report:
//   - mark a non-critical check as not applicable to that class of machine,
//     with a reason (the check still runs; its result is kept in the report);
//   - raise a check's severity (never lower it, never to critical).
//
// It can never change how a check decides pass or fail, so it cannot make a
// weak machine look strong. Profiles are compiled into the binary rather than
// read from a file, so they cannot be edited to hide findings.
package profiles

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Talfaza/hyperion/internal/checks"
)

// Default is the full baseline.
const Default = "server"

type Profile struct {
	Name        string
	Description string
	// NotApplicable maps a check ID to why it does not apply.
	NotApplicable map[string]string
	// Raise maps a check ID to a higher severity, with the reason.
	Raise map[string]Raise
}

type Raise struct {
	To     checks.Severity
	Reason string
}

var builtin = map[string]Profile{
	"server": {
		Name:        "server",
		Description: "Full baseline for production and staging servers.",
	},
	"workstation": {
		Name:        "workstation",
		Description: "Desktops and laptops used by one person.",
		NotApplicable: map[string]string{
			"NET-002":  "desktops use cups for printing and avahi for local discovery",
			"KRN-004":  "developers need debuggers (gdb, strace) that rely on ptrace",
			"KRN-014":  "desktops usually get their IPv6 address from router advertisements (SLAAC)",
			"MNT-002":  "desktop installers use a single root partition",
			"MNT-004":  "desktop installers use a single root partition",
			"MNT-005":  "desktop installers use a single root partition",
			"AUTH-005": "single-user machine; inactivity locking targets shared and server accounts",
		},
		Raise: map[string]Raise{
			"CRY-001": {checks.High, "laptops can be lost or stolen"},
			"CRY-002": {checks.High, "laptops can be lost or stolen"},
		},
	},
	"container-host": {
		Name:        "container-host",
		Description: "Docker hosts and Kubernetes nodes.",
		NotApplicable: map[string]string{
			"KRN-006": "container networking (Docker bridge, Kubernetes CNI) requires IP forwarding",
			"MNT-004": "containers run setuid binaries (sudo, ping) from image layers stored under /var/lib",
		},
	},
}

// Lookup returns a built-in profile by name.
func Lookup(name string) (Profile, error) {
	p, ok := builtin[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	return p, nil
}

// Resolve turns a --profile value into a profile. A comma-separated list
// combines built-in profiles (see Combine).
func Resolve(spec string) (Profile, error) {
	var names []string
	for _, n := range strings.Split(spec, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			return Profile{}, fmt.Errorf("invalid profile list %q: empty name", spec)
		}
		names = append(names, n)
	}
	if len(names) == 1 {
		return Lookup(names[0])
	}
	return Combine(names)
}

// Combine merges several built-in profiles. The result is never weaker than
// its parts would be applied one after another:
//   - a check is not applicable if any part says so (all reasons are kept);
//   - the highest severity raise wins;
//   - if one part raises a check and another marks it not applicable, the
//     check stays, at the raised severity (the stricter outcome).
//
// "server" is the empty baseline and cannot be combined; duplicates and
// unknown names are errors. Parts are sorted so the name is stable.
func Combine(names []string) (Profile, error) {
	parts := slices.Clone(names)
	sort.Strings(parts)
	if slices.Contains(parts, Default) {
		return Profile{}, fmt.Errorf("profile %q is the full baseline and cannot be combined with others", Default)
	}
	for i := 1; i < len(parts); i++ {
		if parts[i] == parts[i-1] {
			return Profile{}, fmt.Errorf("profile %q listed twice", parts[i])
		}
	}

	var list []Profile
	for _, n := range parts {
		p, err := Lookup(n)
		if err != nil {
			return Profile{}, err
		}
		list = append(list, p)
	}
	return merge(list), nil
}

// merge applies the combination rules to already-resolved profiles, given
// in a stable order.
func merge(list []Profile) Profile {
	names := make([]string, len(list))
	for i, p := range list {
		names[i] = p.Name
	}
	combined := Profile{
		Name:          strings.Join(names, "+"),
		NotApplicable: map[string]string{},
		Raise:         map[string]Raise{},
	}
	var descriptions []string
	reasons := map[string][]string{}
	for _, p := range list {
		descriptions = append(descriptions, p.Name+": "+p.Description)
		for id, reason := range p.NotApplicable {
			reasons[id] = append(reasons[id], p.Name+": "+reason)
		}
		for id, r := range p.Raise {
			if cur, ok := combined.Raise[id]; !ok || r.To > cur.To {
				combined.Raise[id] = Raise{To: r.To, Reason: p.Name + ": " + r.Reason}
			}
		}
	}
	for id, rs := range reasons {
		if _, raised := combined.Raise[id]; raised {
			continue // stricter outcome wins
		}
		combined.NotApplicable[id] = strings.Join(rs, "; ")
	}
	combined.Description = "Combination of " + strings.Join(descriptions, " / ")
	return combined
}

// Names lists the built-in profiles, default first.
func Names() []string {
	names := make([]string, 0, len(builtin))
	for n := range builtin {
		if n != Default {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return append([]string{Default}, names...)
}

// ValidateProfile checks one profile, e.g. a combination, against the rules.
func ValidateProfile(p Profile, all []checks.Check) error {
	return validate(map[string]Profile{p.Name: p}, all)
}

// Validate enforces the profile rules against the registered checks. It is
// run by tests and at startup of the CLI, so a bad edit cannot ship.
func Validate(all []checks.Check) error {
	return validate(builtin, all)
}

func validate(table map[string]Profile, all []checks.Check) error {
	byID := map[string]checks.Check{}
	for _, c := range all {
		byID[c.ID] = c
	}
	var problems []string
	for name, p := range table {
		for id, reason := range p.NotApplicable {
			c, ok := byID[id]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: unknown check %s", name, id))
			case c.Severity == checks.Critical:
				problems = append(problems, fmt.Sprintf("%s: critical check %s cannot be not applicable", name, id))
			case strings.TrimSpace(reason) == "":
				problems = append(problems, fmt.Sprintf("%s: %s has no reason", name, id))
			}
		}
		for id, r := range p.Raise {
			c, ok := byID[id]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: unknown check %s", name, id))
			case r.To <= c.Severity:
				problems = append(problems, fmt.Sprintf("%s: %s can only be raised (%s to %s)", name, id, c.Severity, r.To))
			case r.To == checks.Critical:
				problems = append(problems, fmt.Sprintf("%s: %s cannot be raised to critical", name, id))
			case strings.TrimSpace(r.Reason) == "":
				problems = append(problems, fmt.Sprintf("%s: raise of %s has no reason", name, id))
			}
			if _, both := p.NotApplicable[id]; both {
				problems = append(problems, fmt.Sprintf("%s: %s is both raised and not applicable", name, id))
			}
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return fmt.Errorf("invalid profiles: %s", strings.Join(problems, "; "))
	}
	return nil
}
