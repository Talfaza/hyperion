package report

import (
	"strings"
	"unicode"
)

// Sanitize removes control characters (including ESC, so no ANSI sequences)
// from text that originated on the scanned host before it is printed to a
// terminal. A hostile config file or hostname must not be able to rewrite the
// operator's screen, hide findings, or inject terminal escape commands.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case unicode.IsControl(r), r == unicode.ReplacementChar:
			return -1
		case unicode.Is(unicode.Cf, r): // bidi overrides, zero-width chars
			return -1
		}
		return r
	}, s)
}
