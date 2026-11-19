// Package exceptions loads documented risk acceptances (ISO/IEC 27001 Annex A
// A.5.36 deviation tracking): a failing check that the organization has
// reviewed and accepted, with a reason, a compensating control, an approver
// and an expiry date.
//
// Exceptions weaken a security report, so loading fails closed: the file must
// be protected (see platform.ReadTrustedFile) and every entry must be valid,
// or the scan stops. Critical checks can never be excepted.
package exceptions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
	"unicode"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/platform"
)

// DefaultPath is read when it exists; a missing default file means no
// exceptions.
const DefaultPath = "/etc/hyperion/exceptions.json"

const (
	FormatVersion = 1
	// MaxValidity is how far in the future an expiry may be set.
	MaxValidity = 366 * 24 * time.Hour
	minTextLen  = 10
	maxTextLen  = 500
	maxEntries  = 200
)

// Exception is one accepted deviation, as written in the file.
type Exception struct {
	Check               string `json:"check"`
	Reason              string `json:"reason"`
	CompensatingControl string `json:"compensating_control"`
	ApprovedBy          string `json:"approved_by"`
	Expires             string `json:"expires"` // YYYY-MM-DD, end of that day UTC

	expiry time.Time
}

// Expired reports whether the exception no longer applies at now.
func (e Exception) Expired(now time.Time) bool {
	return !now.Before(e.expiry)
}

type file struct {
	Version    int         `json:"version"`
	Exceptions []Exception `json:"exceptions"`
}

// Set is a validated exceptions file.
type Set struct {
	Path   string
	SHA256 string
	byID   map[string]Exception
}

// Lookup returns the exception for a check ID.
func (s *Set) Lookup(id string) (Exception, bool) {
	if s == nil {
		return Exception{}, false
	}
	e, ok := s.byID[id]
	return e, ok
}

// IDs returns every excepted check ID.
func (s *Set) IDs() []string {
	if s == nil {
		return nil
	}
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	return ids
}

// Load reads and validates the exceptions file at path. If path is the
// default and does not exist, it returns (nil, nil). uid is the scanner's
// effective uid, used for the ownership rule.
func Load(path string, explicit bool, uid int, all []checks.Check, now time.Time) (*Set, error) {
	data, err := platform.ReadTrustedFile(path, uid)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("exceptions file: %w", err)
	}
	set, err := Parse(data, all, now)
	if err != nil {
		return nil, fmt.Errorf("exceptions file %s: %w", path, err)
	}
	set.Path = path
	return set, nil
}

// Parse validates the file contents. Any problem is an error: a partially
// applied exceptions file would silently change verdicts.
func Parse(data []byte, all []checks.Check, now time.Time) (*Set, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("invalid JSON: trailing data after the top-level object")
	}
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("unsupported version %d (want %d)", f.Version, FormatVersion)
	}
	if len(f.Exceptions) > maxEntries {
		return nil, fmt.Errorf("%d exceptions (at most %d)", len(f.Exceptions), maxEntries)
	}

	known := map[string]checks.Check{}
	for _, c := range all {
		known[c.ID] = c
	}

	sum := sha256.Sum256(data)
	set := &Set{SHA256: hex.EncodeToString(sum[:]), byID: map[string]Exception{}}
	var problems []string
	for i, e := range f.Exceptions {
		where := fmt.Sprintf("exception %d (%s)", i+1, e.Check)
		c, ok := known[e.Check]
		switch {
		case e.Check == "":
			problems = append(problems, fmt.Sprintf("exception %d: missing check", i+1))
			continue
		case !ok:
			problems = append(problems, where+": unknown check ID")
			continue
		case c.Severity == checks.Critical:
			problems = append(problems, where+": critical checks cannot be excepted")
			continue
		}
		if _, dup := set.byID[e.Check]; dup {
			problems = append(problems, where+": duplicate exception for this check")
			continue
		}
		for _, field := range []struct{ name, value string }{
			{"reason", e.Reason},
			{"compensating_control", e.CompensatingControl},
			{"approved_by", e.ApprovedBy},
		} {
			if msg := validText(field.name, field.value); msg != "" {
				problems = append(problems, where+": "+msg)
			}
		}
		expires, err := time.Parse(time.DateOnly, e.Expires)
		if err != nil {
			problems = append(problems, where+": expires must be a date like 2027-06-30")
			continue
		}
		// Valid through the end of the expiry day (UTC).
		e.expiry = expires.Add(24 * time.Hour)
		if e.expiry.Sub(now) > MaxValidity {
			problems = append(problems, where+": expires more than one year from today; re-approve yearly")
			continue
		}
		set.byID[e.Check] = e
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return set, nil
}

// validText enforces non-trivial, printable justification text. The minimum
// length keeps placeholders like "ok" or "n/a" out of an audit trail.
func validText(name, v string) string {
	trimmed := strings.TrimSpace(v)
	min := minTextLen
	if name == "approved_by" {
		min = 2
	}
	switch {
	case len(trimmed) < min:
		return fmt.Sprintf("%s must be at least %d characters", name, min)
	case len(v) > maxTextLen:
		return fmt.Sprintf("%s must be at most %d characters", name, maxTextLen)
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Sprintf("%s contains control or invisible characters", name)
		}
	}
	return ""
}
